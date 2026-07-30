//nolint:goconst // Hostile fixture path repetition keeps each attack case self-contained.
package interop

import (
	"archive/tar"
	"bytes"
	"testing"
)

// TestInspectArchiveRejectsLinksEscapeCollisionsAndBounds freezes hostile-tree policy.
func TestInspectArchiveRejectsLinksEscapeCollisionsAndBounds(t *testing.T) {
	tests := []struct {
		name    string
		headers []tar.Header
	}{
		{name: "path escape", headers: []tar.Header{{Name: "../escape", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}}},
		{name: "symlink", headers: []tar.Header{{Name: "source/link", Mode: 0o700, Linkname: "/host", Typeflag: tar.TypeSymlink}}},
		{name: "hardlink", headers: []tar.Header{{Name: "source/link", Mode: 0o700, Linkname: "source/file", Typeflag: tar.TypeLink}}},
		{name: "case collision", headers: []tar.Header{
			{Name: "source/File", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg},
			{Name: "source/file", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg},
		}},
		{name: "non ascii", headers: []tar.Header{{Name: "source/\u212aey", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}}},
		{name: "oversize", headers: []tar.Header{{Name: "source/file", Mode: 0o600, Size: 4097, Typeflag: tar.TypeReg}}},
		{name: "owner unreadable", headers: []tar.Header{{Name: "source/file", Mode: 0o222, Size: 1, Typeflag: tar.TypeReg}}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			input := archiveForTest(t, testCase.headers)
			if _, err := InspectArchive(bytes.NewReader(input), archivePolicyForTest()); err == nil {
				t.Fatal("InspectArchive accepted hostile archive")
			}
		})
	}
}

// TestInspectArchiveReturnsSortedContentIdentities proves stable non-extracting output.
func TestInspectArchiveReturnsSortedContentIdentities(t *testing.T) {
	input := archiveForTest(t, []tar.Header{
		{Name: "source/z", Mode: 0o700, Size: 1, Typeflag: tar.TypeReg},
		{Name: "source/a", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg},
	})
	entries, err := InspectArchive(bytes.NewReader(input), archivePolicyForTest())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Path != "source/a" || entries[1].Path != "source/z" ||
		entries[0].SHA256 != entries[1].SHA256 {
		t.Fatalf("entries = %#v", entries)
	}
}

// FuzzInspectArchive proves hostile archive bytes remain bounded and panic-free.
func FuzzInspectArchive(f *testing.F) {
	seed := archiveForFuzzSeed()
	f.Add(seed)
	f.Add([]byte("not a tar"))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if len(input) > 16384 {
			input = input[:16384]
		}
		policy := archivePolicyForTest()
		policy.MaxResponseBytes = 16384
		_, _ = InspectArchive(bytes.NewReader(input), policy)
	})
}

// archiveForTest constructs one exact tar stream for a hostile policy case.
func archiveForTest(t *testing.T, headers []tar.Header) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for index := range headers {
		header := headers[index]
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			content := bytes.Repeat([]byte{'x'}, int(header.Size))
			if _, err := writer.Write(content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

// archiveForFuzzSeed constructs one minimal valid source archive.
func archiveForFuzzSeed() []byte {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	_ = writer.WriteHeader(&tar.Header{Name: "source/file", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
	_, _ = writer.Write([]byte{'x'})
	_ = writer.Close()
	return output.Bytes()
}

// archivePolicyForTest returns tight deterministic archive bounds.
func archivePolicyForTest() RetrievalPolicy {
	return RetrievalPolicy{
		MaxRedirects: 1, MaxResponseBytes: 16384, MaxFiles: 8, MaxFileBytes: 4096,
		MaxTotalBytes: 8192, MaxPathBytes: 256, MaxDepth: 8, TimeoutSeconds: 5,
	}
}
