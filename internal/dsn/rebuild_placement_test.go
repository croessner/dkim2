package dsn

import (
	"bytes"
	"strings"
	"testing"
)

const (
	placementRemoteReceived = "Received: from origin by remote (present-on-arrival)\r\n"
	placementLocalReceived  = "Received: from remote by local (added-by-local-hop)\r\n"
	placementDestReceived   = "Received: from local by destination (added-downstream)\r\n"
	placementLocalInfo      = "X-DKIM2-Info: local-hop-diagnostic\r\n"
)

// Layout tokens select the built or inserted fields of a placement layout.
const (
	tokPrevInstance   = "MI1"
	tokPrevSignature  = "DS1"
	tokLocalInstance  = "MI2"
	tokLocalSignature = "DS2"
	tokRemoteReceived = "RREMOTE"
	tokBase           = "BASE"
	tokLocalReceived  = "RLOCAL"
	tokDestReceived   = "RDEST"
	tokLocalInfo      = "INFO"
	// placementKeptNames is the rebuilt order when the previous hop's own
	// Received field survives above the signed base fields.
	placementKeptNames = "message-instance,dkim2-signature,received,from,subject,message-id"
	// placementDroppedNames is the rebuilt order when every unsigned field sat
	// above a bottom-placed previous hop signature.
	placementDroppedNames = "from,subject,message-id,message-instance,dkim2-signature"
)

// splitPlacementFields splits a built CRLF original into its header fields
// and the separator-prefixed remainder, keeping continuation lines attached.
func splitPlacementFields(raw []byte) ([]string, []byte) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, nil
	}
	block, rest := string(raw[:end+2]), raw[end+2:]
	var fields []string
	for block != "" {
		lineEnd := strings.Index(block, "\r\n") + 2
		if block[0] == ' ' || block[0] == '\t' {
			fields[len(fields)-1] += block[:lineEnd]
		} else {
			fields = append(fields, block[:lineEnd])
		}
		block = block[lineEnd:]
	}
	return fields, rest
}

// placementLayout re-renders a built two-hop original in the given top-down
// layout. The tokens MI1, DS1 (previous hop), MI2, DS2 (local hop), RREMOTE
// (the previous hop's own Received field), and BASE (the remaining signed
// fields in wire order) select built fields; RLOCAL, RDEST, and INFO insert
// the unsigned fields the local hop and the downstream destination add.
func placementLayout(layout ...string) func([]byte) []byte {
	return func(raw []byte) []byte {
		fields, rest := splitPlacementFields(raw)
		selected := map[string]string{}
		var base strings.Builder
		for _, field := range fields {
			switch {
			case strings.HasPrefix(field, "Message-Instance: m=1;"):
				selected[tokPrevInstance] = field
			case strings.HasPrefix(field, "Message-Instance: m=2;"):
				selected[tokLocalInstance] = field
			case strings.HasPrefix(field, "DKIM2-Signature: i=1;"):
				selected[tokPrevSignature] = field
			case strings.HasPrefix(field, "DKIM2-Signature: i=2;"):
				selected[tokLocalSignature] = field
			case field == placementRemoteReceived:
				selected[tokRemoteReceived] = field
			default:
				base.WriteString(field)
			}
		}
		selected[tokBase] = base.String()
		selected[tokLocalReceived] = placementLocalReceived
		selected[tokDestReceived] = placementDestReceived
		selected[tokLocalInfo] = placementLocalInfo
		var output strings.Builder
		for _, token := range layout {
			field, ok := selected[token]
			if !ok {
				return nil
			}
			output.WriteString(field)
		}
		return append([]byte(output.String()), rest...)
	}
}

// placementOriginal returns the forwarded two-hop chain whose current and
// previous states both carry the previous hop's own Received field.
func placementOriginal() propagationSpec {
	original := defaultPropagationOriginal(rebuildFullRecipe)
	original.Headers = placementRemoteReceived + rebuildCurrentHeaders
	original.Revisions[0].Headers = placementRemoteReceived + rebuildOriginHeaders
	return propagationSpec{original: original}
}

// TestRebuildAcceptsEveryTraceFieldPlacement proves the Section 16.3 rebuild
// does not depend on whether either hop prepended (top-placed) or appended
// (bottom-placed) its Message-Instance and DKIM2-Signature fields. It always
// removes the local hop's protocol fields and every unsigned field above the
// previous hop's signature, restores the previous state, and verifies it.
// Top placement of the previous hop is what lets the good-faith unsigned-field
// removal keep the previous hop's own Received field: only fields added after
// arrival sit above its signature. With a bottom-placed previous hop every
// unsigned field is above that signature, so the rebuild also removes
// unsigned fields that were present on arrival. That over-removal is safe
// because Section 4 excludes them from every hash, and the Section 16.3
// removal of unsigned fields is SHOULD-level good-faith effort.
func TestRebuildAcceptsEveryTraceFieldPlacement(t *testing.T) {
	for _, test := range []struct {
		name         string
		layout       []string
		headersOnly  bool
		wantReceived []string
		wantNames    string
	}{
		{
			name:         "both hops top-placed",
			layout:       []string{tokDestReceived, tokLocalInstance, tokLocalSignature, tokLocalInfo, tokLocalReceived, tokPrevInstance, tokPrevSignature, tokRemoteReceived, tokBase},
			wantReceived: []string{placementRemoteReceived},
			wantNames:    placementKeptNames,
		},
		{
			name:      "both hops bottom-placed",
			layout:    []string{tokDestReceived, tokLocalReceived, tokRemoteReceived, tokBase, tokPrevInstance, tokPrevSignature, tokLocalInstance, tokLocalSignature},
			wantNames: placementDroppedNames,
		},
		{
			name:      "previous hop bottom-placed and local hop top-placed",
			layout:    []string{tokDestReceived, tokLocalInstance, tokLocalSignature, tokLocalInfo, tokLocalReceived, tokRemoteReceived, tokBase, tokPrevInstance, tokPrevSignature},
			wantNames: placementDroppedNames,
		},
		{
			name:         "previous hop top-placed and local hop bottom-placed",
			layout:       []string{tokDestReceived, tokLocalReceived, tokPrevInstance, tokPrevSignature, tokRemoteReceived, tokBase, tokLocalInstance, tokLocalSignature},
			wantReceived: []string{placementRemoteReceived},
			wantNames:    placementKeptNames,
		},
		{
			name:         "headers-only rebuild of top-placed hops",
			layout:       []string{tokDestReceived, tokLocalInstance, tokLocalSignature, tokLocalInfo, tokLocalReceived, tokPrevInstance, tokPrevSignature, tokRemoteReceived, tokBase},
			headersOnly:  true,
			wantReceived: []string{placementRemoteReceived},
			wantNames:    placementKeptNames,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := placementOriginal()
			spec.mutate = placementLayout(test.layout...)
			spec.headersOnly = test.headersOnly
			report, _ := mustRebuild(t, spec)
			if test.headersOnly != (report.Form() == EvidenceFormHeadersOnly) {
				t.Fatalf("rebuilt form=%q", report.Form())
			}
			_, _, embedded := mustParseRebuilt(t, report.Bytes())
			headers := embedded.Headers()
			if got := strings.Join(headerNames(headers), ","); got != test.wantNames {
				t.Fatalf("rebuilt header order=%s want=%s", got, test.wantNames)
			}
			received := headers.FieldsByName("received")
			if len(received) != len(test.wantReceived) {
				t.Fatalf("received fields=%d want=%d", len(received), len(test.wantReceived))
			}
			for index, want := range test.wantReceived {
				if string(received[index].OriginalBytes()) != want {
					t.Fatalf("received[%d]=%q", index, received[index].OriginalBytes())
				}
			}
			instances := headers.FieldsByName("message-instance")
			signatures := headers.FieldsByName("dkim2-signature")
			if len(instances) != 1 || !bytes.HasPrefix(instances[0].OriginalBytes(), []byte("Message-Instance: m=1;")) ||
				len(signatures) != 1 || !bytes.HasPrefix(signatures[0].OriginalBytes(), []byte("DKIM2-Signature: i=1;")) {
				t.Fatal("rebuild did not keep exactly the previous hop's protocol fields")
			}
			subject, _ := headers.LastFieldByName(rebuildSubjectName)
			if string(subject.UnfoldedValue()) != rebuildOriginSubject {
				t.Fatalf("subject=%q", subject.UnfoldedValue())
			}
			for _, leaked := range []string{"added-by-local-hop", "added-downstream", "local-hop-diagnostic"} {
				if strings.Contains(string(report.Bytes()), leaked) {
					t.Fatalf("rebuilt report kept %q", leaked)
				}
			}
		})
	}
}
