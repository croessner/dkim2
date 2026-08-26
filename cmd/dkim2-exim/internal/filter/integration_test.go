package filter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

// TestGeneratedClientFilterFlow proves both operations traverse the generated
// HTTP client, strict raw response admission, and complete LF output.
func TestGeneratedClientFilterFlow(t *testing.T) {
	tests := []struct {
		name       string
		operation  adapter.FilterOperation
		arguments  []string
		response   generated.OperationResponse
		wantOutput []byte
	}{
		{
			name:      "sign",
			operation: adapter.FilterSign,
			arguments: []string{"", testTransportRecipient},
			response: generated.OperationResponse{
				Actions: generated.ActionPlan{
					{Type: generated.AddHeader, Name: generated.MessageInstance, Value: " i=1; m=a"},
					{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: " i=1; s=a"},
				},
				ApiVersion: generated.V1, Disposition: generated.DispositionAccept,
				Draft:     generated.DraftIetfDkimDkim2Spec05,
				Operation: generated.Sign, Result: generated.OperationResponseResultPass,
			},
			wantOutput: []byte(
				"Subject: \xc3\xa9\n" +
					"Message-Instance: i=1; m=a\n" +
					"DKIM2-Signature: i=1; s=a\n\n" +
					"lf\ncrlf\r\nnul\x00utf8\xf0\x9f\x93\xa8\n",
			),
		},
		{
			name:      "revise",
			operation: adapter.FilterRevise,
			arguments: []string{
				testLocator,
				testOutgoingSender,
				"<batch@example.test>",
			},
			response: generated.OperationResponse{
				Actions: generated.ActionPlan{
					{Type: generated.AddHeader, Name: generated.DKIM2Signature, Value: " i=2; s=b"},
				},
				ApiVersion: generated.V1, Disposition: generated.DispositionAccept,
				Draft:     generated.DraftIetfDkimDkim2Spec05,
				Operation: generated.Revise, Result: generated.OperationResponseResultPass,
			},
			wantOutput: []byte(
				"Subject: \xc3\xa9\n" +
					"DKIM2-Signature: i=2; s=b\n\n" +
					"lf\ncrlf\r\nnul\x00utf8\xf0\x9f\x93\xa8\n",
			),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				assertGeneratedFilterRequest(t, request, testCase.operation)
				writer.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(writer).Encode(testCase.response); err != nil {
					t.Fatal("generated response fixture failed")
				}
			}))
			defer server.Close()

			client, err := generated.NewClient(server.URL)
			if err != nil {
				t.Fatal("generated client construction failed")
			}
			processor, err := daemon.NewFilterProcessor(
				client,
				"tenant",
				"example.test",
			)
			if err != nil {
				t.Fatal("filter processor construction failed")
			}
			incoming, _ := adapter.NewIncomingEvidence(
				[]byte("<incoming@example.test>"),
				[][]byte{[]byte("<received@example.test>")},
				adapter.SessionSMTP,
			)
			loader := &evidenceStub{incoming: incoming}
			input := []byte(
				"Subject: \xc3\xa9\n\n" +
					"lf\ncrlf\r\nnul\x00utf8\xf0\x9f\x93\xa8",
			)
			var output bytes.Buffer
			status := Execute(context.Background(), RunConfig{
				Operation: testCase.operation,
				Arguments: testCase.arguments,
				Input:     bytes.NewReader(input),
				Output:    &output,
				Loader:    loader,
				Processor: processor,
				TempDir:   t.TempDir(),
			})
			if status != ExitSuccess || !bytes.Equal(output.Bytes(), testCase.wantOutput) {
				t.Fatal("generated-client filter flow changed protocol output")
			}
			if testCase.operation == adapter.FilterSign && loader.calls != 0 ||
				testCase.operation == adapter.FilterRevise && loader.calls != 1 {
				t.Fatal("generated-client flow used incorrect evidence authority")
			}
		})
	}
}

// assertGeneratedFilterRequest independently checks operation path and exact
// CRLF message projection without formatting protected envelope members.
func assertGeneratedFilterRequest(
	t *testing.T,
	request *http.Request,
	operation adapter.FilterOperation,
) {
	t.Helper()
	wantPath := "/v1/sign"
	if operation == adapter.FilterRevise {
		wantPath = "/v1/revise"
	}
	if request.Method != http.MethodPost || request.URL.Path != wantPath {
		t.Fatal("generated client selected incorrect daemon operation")
	}
	var message generated.MessageInput
	switch operation {
	case adapter.FilterSign:
		var value generated.SignRequest
		if err := json.NewDecoder(request.Body).Decode(&value); err != nil {
			t.Fatal("generated sign request decode failed")
		}
		message = value.Message
	case adapter.FilterRevise:
		var value generated.ReviseRequest
		if err := json.NewDecoder(request.Body).Decode(&value); err != nil {
			t.Fatal("generated revise request decode failed")
		}
		incomingSender, _ := value.IncomingSmtp.MailFrom.Bytes()
		outgoingSender, _ := value.Smtp.MailFrom.Bytes()
		defer clear(incomingSender)
		defer clear(outgoingSender)
		if string(incomingSender) != "<incoming@example.test>" ||
			string(outgoingSender) != testOutgoingSender {
			t.Fatal("generated revise request conflated envelope authorities")
		}
		message = value.Message
	default:
		t.Fatal("invalid filter operation reached generated client")
	}
	encoded, err := message.RawRfc5322Base64.Bytes()
	if err != nil {
		t.Fatal("generated message member was invalid")
	}
	defer clear(encoded)
	raw, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil {
		t.Fatal("generated message was not canonical base64")
	}
	defer clear(raw)
	want := []byte(
		"Subject: \xc3\xa9\r\n\r\n" +
			"lf\r\ncrlf\r\nnul\x00utf8\xf0\x9f\x93\xa8\r\n",
	)
	if !bytes.Equal(raw, want) {
		t.Fatal("generated daemon request changed CRLF or binary message bytes")
	}
}
