package signingstore

import "testing"

// FuzzPrivateManifestParsingNeverPanics exercises the closed protected-key schema.
func FuzzPrivateManifestParsingNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":"dkim2-private-keys-v1","entries":[]}`))
	f.Add([]byte(`{"version":"dkim2-private-keys-v1","entries":[{}]}`))
	f.Add([]byte{0, 0xff, '{'})
	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > maxManifestBytes {
			document = document[:maxManifestBytes]
		}
		entries, err := decodeManifest(document)
		if err != nil {
			return
		}
		if len(entries) < 1 || len(entries) > 1024 {
			t.Fatalf("manifest retained %d entries", len(entries))
		}
	})
}
