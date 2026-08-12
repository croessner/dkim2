package valkey

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

// trackingReader records how many protected wire bytes the decoder consumed.
type trackingReader struct {
	reader io.Reader
	read   int
}

// Read delegates one read while retaining only its byte count.
func (r *trackingReader) Read(destination []byte) (int, error) {
	count, err := r.reader.Read(destination)
	r.read += count
	return count, err
}

// TestRESP2DecoderAcceptsFrozenTypes proves the decoder's complete scalar and array vocabulary.
func TestRESP2DecoderAcceptsFrozenTypes(t *testing.T) {
	tests := []struct {
		name        string
		frame       string
		kind        resp2Kind
		bytes       string
		integer     int64
		elementKind []resp2Kind
	}{
		{name: "simple string", frame: "+OK\r\n", kind: resp2SimpleString, bytes: "OK"},
		{name: "error", frame: "-NOAUTH protected suffix\r\n", kind: resp2Error, bytes: "NOAUTH protected suffix"},
		{name: "zero integer", frame: ":0\r\n", kind: resp2Integer},
		{name: "negative integer", frame: ":-42\r\n", kind: resp2Integer, integer: -42},
		{name: "maximum integer", frame: ":9223372036854775807\r\n", kind: resp2Integer, integer: 9223372036854775807},
		{name: "minimum integer", frame: ":-9223372036854775808\r\n", kind: resp2Integer, integer: -9223372036854775808},
		{name: "bulk string", frame: "$3\r\nfoo\r\n", kind: resp2BulkString, bytes: "foo"},
		{name: "empty bulk string", frame: "$0\r\n\r\n", kind: resp2BulkString},
		{name: "null bulk", frame: "$-1\r\n", kind: resp2NullBulk},
		{
			name:        "array",
			frame:       "*5\r\n+OK\r\n-ERR denied\r\n:7\r\n$1\r\nx\r\n$-1\r\n",
			kind:        resp2Array,
			elementKind: []resp2Kind{resp2SimpleString, resp2Error, resp2Integer, resp2BulkString, resp2NullBulk},
		},
		{name: "empty array", frame: "*0\r\n", kind: resp2Array},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := newRESP2Decoder(strings.NewReader(test.frame))
			value, err := decoder.decode()
			if err != nil {
				t.Fatal("valid frozen RESP2 frame was rejected")
			}
			t.Cleanup(decoder.clear)

			if value.kind != test.kind {
				t.Fatalf("kind = %d, want %d", value.kind, test.kind)
			}
			if string(value.bytes) != test.bytes {
				t.Fatal("decoded scalar bytes differ")
			}
			if value.integer != test.integer {
				t.Fatalf("decoded integer = %d, want %d", value.integer, test.integer)
			}
			if len(value.values) != len(test.elementKind) {
				t.Fatalf("array length = %d, want %d", len(value.values), len(test.elementKind))
			}
			for index, want := range test.elementKind {
				if value.values[index].kind != want {
					t.Fatalf("array element %d kind = %d, want %d", index, value.values[index].kind, want)
				}
			}
		})
	}
}

// TestRESP2DecoderRejectsUnsupportedAndMalformedFrames proves strict fail-closed framing.
func TestRESP2DecoderRejectsUnsupportedAndMalformedFrames(t *testing.T) {
	tests := []struct {
		name  string
		frame string
	}{
		{name: testNameEmpty, frame: ""},
		{name: "lone prefix", frame: "+"},
		{name: "bare newline", frame: "+OK\n"},
		{name: "invalid CRLF", frame: "+OK\rX"},
		{name: "embedded bare newline", frame: "+O\nK\r\n"},
		{name: "empty integer", frame: ":\r\n"},
		{name: "integer plus only", frame: ":+\r\n"},
		{name: "integer overflow positive", frame: ":" + canonicalInt64OverflowText + "\r\n"},
		{name: "integer overflow negative", frame: ":-9223372036854775809\r\n"},
		{name: "bulk negative non-null", frame: "$-2\r\n"},
		{name: "bulk explicit plus", frame: "$+1\r\nx\r\n"},
		{name: "bulk leading zero", frame: "$01\r\nx\r\n"},
		{name: "bulk length overflow", frame: "$" + canonicalInt64OverflowText + "\r\n"},
		{name: "bulk truncated payload", frame: "$3\r\nfo"},
		{name: "bulk missing trailer", frame: "$3\r\nfoo"},
		{name: "bulk invalid trailer", frame: "$3\r\nfoo\n\n"},
		{name: "null array", frame: "*-1\r\n"},
		{name: "array explicit plus", frame: "*+1\r\n$-1\r\n"},
		{name: "array leading zero", frame: "*01\r\n$-1\r\n"},
		{name: "array length overflow", frame: "*" + canonicalInt64OverflowText + "\r\n"},
		{name: "array truncated child", frame: "*1\r\n"},
		{name: "RESP3 null", frame: "_\r\n"},
		{name: "RESP3 boolean", frame: "#t\r\n"},
		{name: "RESP3 double", frame: ",1.0\r\n"},
		{name: "RESP3 big number", frame: "(1\r\n"},
		{name: "RESP3 bulk error", frame: "!3\r\nERR\r\n"},
		{name: "RESP3 verbatim string", frame: "=3\r\ntxt\r\n"},
		{name: "RESP3 map", frame: "%0\r\n"},
		{name: "RESP3 set", frame: "~0\r\n"},
		{name: "RESP3 push", frame: ">0\r\n"},
		{name: "inline command", frame: "PING\r\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := newRESP2Decoder(strings.NewReader(test.frame))
			_, err := decoder.decode()
			if err == nil {
				t.Fatal("unsupported or malformed RESP frame was accepted")
			}
			if test.frame != "" && strings.Contains(err.Error(), test.frame) {
				t.Fatal("decoder error exposed protected reply bytes")
			}
			decoder.clear()
			if !decoder.bufferCleared() {
				t.Fatal("decoder retained protected reply bytes after clear")
			}
		})
	}
}

// TestRESP2IntegerParsingEnforcesExactSignedInt64 proves canonical byte-native integer bounds.
func TestRESP2IntegerParsingEnforcesExactSignedInt64(t *testing.T) {
	accepted := []struct {
		text string
		want int64
	}{
		{text: "0", want: 0},
		{text: "1", want: 1},
		{text: "-1", want: -1},
		{text: "9223372036854775807", want: 9223372036854775807},
		{text: "-9223372036854775808", want: -9223372036854775808},
	}
	for _, test := range accepted {
		value, valid := parseRESPInteger([]byte(test.text))
		if !valid || value != test.want {
			t.Fatalf("parseRESPInteger(%q) = (%d, %t), want (%d, true)", test.text, value, valid, test.want)
		}
	}

	rejected := []string{
		"",
		"+1",
		"00",
		"-0",
		"-01",
		canonicalInt64OverflowText,
		"-9223372036854775809",
		"1x",
	}
	for _, text := range rejected {
		if _, valid := parseRESPInteger([]byte(text)); valid {
			t.Fatalf("parseRESPInteger(%q) accepted a noncanonical or overflowing value", text)
		}
	}
}

// TestRESP2CountParsingEnforcesCanonicalBounds proves exact null and 4 KiB count semantics.
func TestRESP2CountParsingEnforcesCanonicalBounds(t *testing.T) {
	accepted := []struct {
		text      string
		allowNull bool
		want      int
		null      bool
	}{
		{text: "0", want: 0},
		{text: "1", want: 1},
		{text: "4096", want: 4096},
		{text: "-1", allowNull: true, null: true},
	}
	for _, test := range accepted {
		count, null, valid := parseRESPCount([]byte(test.text), test.allowNull)
		if !valid || count != test.want || null != test.null {
			t.Fatalf(
				"parseRESPCount(%q, %t) = (%d, %t, %t), want (%d, %t, true)",
				test.text,
				test.allowNull,
				count,
				null,
				valid,
				test.want,
				test.null,
			)
		}
	}

	rejected := []struct {
		text      string
		allowNull bool
	}{
		{text: ""},
		{text: "+1"},
		{text: "00"},
		{text: "-0"},
		{text: "-1"},
		{text: "-2", allowNull: true},
		{text: "4097"},
		{text: canonicalInt64OverflowText},
		{text: "1x"},
	}
	for _, test := range rejected {
		if _, _, valid := parseRESPCount([]byte(test.text), test.allowNull); valid {
			t.Fatalf("parseRESPCount(%q, %t) accepted a noncanonical or overflowing value", test.text, test.allowNull)
		}
	}
}

// TestRESP2DecoderPrivacyBoundary rejects immutable protected-byte copies and unsafe parsing.
func TestRESP2DecoderPrivacyBoundary(t *testing.T) {
	source, err := os.ReadFile("resp2.go")
	if err != nil {
		t.Fatalf("read RESP2 decoder source: %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "resp2.go", source, 0)
	if err != nil {
		t.Fatalf("parse RESP2 decoder source: %v", err)
	}

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		identifier, ok := call.Fun.(*ast.Ident)
		if ok && identifier.Name == panicPointString {
			t.Error("RESP2 decoder converts protected bytes to immutable string")
		}
		return true
	})
	for _, imported := range file.Imports {
		if imported.Path.Value == `"strconv"` || imported.Path.Value == `"unsafe"` {
			t.Errorf("RESP2 decoder imports privacy-unsafe parser %s", imported.Path.Value)
		}
	}
}

// TestRESP2DecoderChecksDeclaredLengthsBeforeContentRead proves hostile declarations fail before payload work.
func TestRESP2DecoderChecksDeclaredLengthsBeforeContentRead(t *testing.T) {
	tests := []struct {
		name   string
		header string
		tail   string
	}{
		{name: "bulk exceeds frame", header: "$4096\r\n", tail: strings.Repeat("s", 4096) + "\r\n"},
		{name: "bulk enormous declaration", header: "$999999999\r\n", tail: "protected"},
		{name: "array exceeds aggregate values", header: "*256\r\n", tail: strings.Repeat("$-1\r\n", 256)},
		{name: "array enormous declaration", header: "*999999999\r\n", tail: "protected"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &trackingReader{reader: strings.NewReader(test.header + test.tail)}
			decoder := newRESP2Decoder(reader)
			_, err := decoder.decode()
			if err == nil {
				t.Fatal("over-limit declaration was accepted")
			}
			if reader.read != len(test.header) {
				t.Fatalf("decoder consumed %d bytes, want declaration-only %d", reader.read, len(test.header))
			}
			decoder.clear()
		})
	}
}

// TestRESP2DecoderEnforcesExactEncodedByteCap proves complete frames at 4096 and 4097 bytes.
func TestRESP2DecoderEnforcesExactEncodedByteCap(t *testing.T) {
	accepted := resp2BulkFrame(4087)
	if len(accepted) != 4096 {
		t.Fatalf("accepted fixture length = %d, want 4096", len(accepted))
	}
	decoder := newRESP2Decoder(strings.NewReader(accepted))
	value, err := decoder.decode()
	if err != nil {
		t.Fatal("exact 4096-byte frame was rejected")
	}
	if value.kind != resp2BulkString || len(value.bytes) != 4087 {
		t.Fatal("exact-cap bulk string decoded incorrectly")
	}
	decoder.clear()

	rejected := resp2BulkFrame(4088)
	if len(rejected) != 4097 {
		t.Fatalf("rejected fixture length = %d, want 4097", len(rejected))
	}
	reader := &trackingReader{reader: strings.NewReader(rejected)}
	decoder = newRESP2Decoder(reader)
	if _, err = decoder.decode(); err == nil {
		t.Fatal("4097-byte frame was accepted")
	}
	const declarationBytes = len("$4088\r\n")
	if reader.read != declarationBytes {
		t.Fatalf("decoder consumed %d bytes, want declaration-only %d", reader.read, declarationBytes)
	}
	decoder.clear()
}

// TestRESP2DecoderEnforcesAggregateValueCap proves root-inclusive 256/257 value accounting.
func TestRESP2DecoderEnforcesAggregateValueCap(t *testing.T) {
	accepted := "*" + strconv.Itoa(255) + "\r\n" + strings.Repeat("$-1\r\n", 255)
	decoder := newRESP2Decoder(strings.NewReader(accepted))
	value, err := decoder.decode()
	if err != nil {
		t.Fatal("256 aggregate RESP values were rejected")
	}
	if value.kind != resp2Array || len(value.values) != 255 {
		t.Fatal("256-value boundary decoded incorrectly")
	}
	decoder.clear()

	const rejectedHeader = "*256\r\n"
	rejected := rejectedHeader + strings.Repeat("$-1\r\n", 256)
	reader := &trackingReader{reader: strings.NewReader(rejected)}
	decoder = newRESP2Decoder(reader)
	if _, err = decoder.decode(); err == nil {
		t.Fatal("257 aggregate RESP values were accepted")
	}
	if reader.read != len(rejectedHeader) {
		t.Fatalf("decoder consumed %d bytes, want declaration-only %d", reader.read, len(rejectedHeader))
	}
	decoder.clear()
}

// TestRESP2DecoderEnforcesContainerDepth proves six nested root-inclusive arrays and rejects seven.
func TestRESP2DecoderEnforcesContainerDepth(t *testing.T) {
	accepted := strings.Repeat("*1\r\n", 6) + "$-1\r\n"
	decoder := newRESP2Decoder(strings.NewReader(accepted))
	value, err := decoder.decode()
	if err != nil {
		t.Fatal("six container levels were rejected")
	}
	for level := range 6 {
		if value.kind != resp2Array || len(value.values) != 1 {
			t.Fatalf("container level %d decoded incorrectly", level+1)
		}
		value = value.values[0]
	}
	if value.kind != resp2NullBulk {
		t.Fatal("leaf at six-container boundary decoded incorrectly")
	}
	decoder.clear()

	seventhHeader := strings.Repeat("*1\r\n", 7)
	reader := &trackingReader{reader: strings.NewReader(seventhHeader + "$-1\r\n")}
	decoder = newRESP2Decoder(reader)
	if _, err = decoder.decode(); err == nil {
		t.Fatal("seven container levels were accepted")
	}
	if reader.read != len(seventhHeader) {
		t.Fatalf("decoder consumed %d bytes, want seven declarations %d", reader.read, len(seventhHeader))
	}
	decoder.clear()
}

// TestRESP2DecoderEnforcesControlLineCap proves the 511/512/513 content-byte boundary for every line use.
func TestRESP2DecoderEnforcesControlLineCap(t *testing.T) {
	lineKinds := []struct {
		name   string
		decode func(*resp2Decoder) (resp2Value, error)
		frame  func(string) string
	}{
		{
			name: "control",
			decode: func(decoder *resp2Decoder) (resp2Value, error) {
				value, err := decoder.readControlLine()
				return resp2Value{bytes: value}, err
			},
			frame: func(content string) string { return content + "\r\n" },
		},
		{
			name:   "simple",
			decode: (*resp2Decoder).decode,
			frame:  func(content string) string { return "+" + content + "\r\n" },
		},
		{
			name:   "error",
			decode: (*resp2Decoder).decode,
			frame:  func(content string) string { return "-" + content + "\r\n" },
		},
	}
	boundaries := []struct {
		contentBytes int
		accepted     bool
	}{
		{contentBytes: 511, accepted: true},
		{contentBytes: 512, accepted: true},
		{contentBytes: 513, accepted: false},
	}

	for _, lineKind := range lineKinds {
		for _, boundary := range boundaries {
			t.Run(lineKind.name+"/"+strconv.Itoa(boundary.contentBytes), func(t *testing.T) {
				content := strings.Repeat("x", boundary.contentBytes)
				decoder := newRESP2Decoder(strings.NewReader(lineKind.frame(content)))
				t.Cleanup(decoder.clear)

				value, err := lineKind.decode(decoder)
				if boundary.accepted {
					if err != nil {
						t.Fatalf("%d content bytes were rejected", boundary.contentBytes)
					}
					if len(value.bytes) != boundary.contentBytes {
						t.Fatalf("decoded %d content bytes, want %d", len(value.bytes), boundary.contentBytes)
					}
					return
				}
				if err == nil {
					t.Fatalf("%d content bytes were accepted", boundary.contentBytes)
				}
			})
		}
	}
}

// TestRESP2InfoLineValidationEnforcesLineCap proves exact CRLF and 512/513 payload-line limits.
func TestRESP2InfoLineValidationEnforcesLineCap(t *testing.T) {
	accepted := [][]byte{
		{},
		[]byte("# Memory\r\nused_memory:1\r\n"),
		append(bytes.Repeat([]byte{'x'}, 512), '\r', '\n'),
	}
	for index, payload := range accepted {
		if err := validateRESP2InfoLineLengths(payload); err != nil {
			t.Fatalf("valid INFO payload %d was rejected", index)
		}
	}

	rejected := [][]byte{
		append(bytes.Repeat([]byte{'x'}, 513), '\r', '\n'),
		[]byte("used_memory:1\n"),
		[]byte("used_memory:1\r"),
		[]byte("used_memory:1\rX"),
		[]byte("used\n_memory:1\r\n"),
	}
	for index, payload := range rejected {
		err := validateRESP2InfoLineLengths(payload)
		if err == nil {
			t.Fatalf("invalid INFO payload %d was accepted", index)
		}
		if strings.Contains(err.Error(), string(payload)) {
			t.Fatalf("INFO validation error %d exposed protected payload", index)
		}
	}
}

// TestRESP2DecoderPreservesAlternatingDuplicates proves ACL-style fields remain ordered and observable.
func TestRESP2DecoderPreservesAlternatingDuplicates(t *testing.T) {
	fields := []string{
		"flags", "on",
		"passwords", "hash-one",
		"commands", "-@all +ping +set",
		"keys", "~dkim2:*",
		"flags", "off",
		"databases", "db=0",
		"selectors", "",
	}
	var frame strings.Builder
	frame.WriteString("*14\r\n")
	for _, field := range fields {
		frame.WriteString("$")
		frame.WriteString(strconv.Itoa(len(field)))
		frame.WriteString("\r\n")
		frame.WriteString(field)
		frame.WriteString("\r\n")
	}

	decoder := newRESP2Decoder(strings.NewReader(frame.String()))
	value, err := decoder.decode()
	if err != nil {
		t.Fatal("valid duplicate-preserving array was rejected")
	}
	if value.kind != resp2Array || len(value.values) != len(fields) {
		t.Fatal("alternating field array shape changed")
	}
	for index, field := range fields {
		if value.values[index].kind != resp2BulkString || string(value.values[index].bytes) != field {
			t.Fatalf("alternating field %d was collapsed or reordered", index)
		}
	}
	decoder.clear()
}

// TestRESP2DecoderClearErasesOwnedBuffer proves protected scalar bytes vanish before release.
func TestRESP2DecoderClearErasesOwnedBuffer(t *testing.T) {
	const protected = "protected-password-material"
	decoder := newRESP2Decoder(strings.NewReader(resp2BulkFrameWithValue(protected)))
	value, err := decoder.decode()
	if err != nil {
		t.Fatal("protected scalar fixture was rejected")
	}
	if string(value.bytes) != protected {
		t.Fatal("protected scalar fixture decoded incorrectly")
	}
	if decoder.bufferCleared() {
		t.Fatal("decoder incorrectly reported a live buffer as cleared")
	}

	decoder.clear()
	if !decoder.bufferCleared() {
		t.Fatal("decoder retained protected reply bytes after clear")
	}
	for _, octet := range value.bytes {
		if octet != 0 {
			t.Fatal("decoded scalar did not alias the cleared owned buffer")
		}
	}

	decoder.clear()
	if !decoder.bufferCleared() {
		t.Fatal("decoder clear was not idempotent")
	}
}

// TestRESP2DecoderErrorsRemainBoundedAndRedacted proves hostile bytes never enter error text.
func TestRESP2DecoderErrorsRemainBoundedAndRedacted(t *testing.T) {
	const protected = "unique-protected-reply-material"
	frame := "$999999999\r\n" + protected
	decoder := newRESP2Decoder(strings.NewReader(frame))
	_, err := decoder.decode()
	if err == nil {
		t.Fatal("hostile protected frame was accepted")
	}
	rendered := fmt.Sprint(err)
	if strings.Contains(rendered, protected) || len(rendered) > 128 {
		t.Fatal("decoder error was unbounded or exposed protected material")
	}
	decoder.clear()
}

// resp2BulkFrame creates a deterministic bulk frame of the requested payload length.
func resp2BulkFrame(length int) string {
	return resp2BulkFrameWithValue(strings.Repeat("x", length))
}

// resp2BulkFrameWithValue creates one exact bulk frame without production helpers.
func resp2BulkFrameWithValue(value string) string {
	return "$" + strconv.Itoa(len(value)) + "\r\n" + value + "\r\n"
}
