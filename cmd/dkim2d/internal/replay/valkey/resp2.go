package valkey

import (
	"errors"
	"io"

	dkim2 "github.com/croessner/dkim2"
)

const (
	maximumAuditReplyBytes = 4096
	maximumRESPValues      = 256
	maximumRESPDepth       = 6
	maximumRESPLineBytes   = 512
)

// resp2Kind identifies one accepted private-auditor RESP2 value type.
type resp2Kind uint8

const (
	resp2SimpleString resp2Kind = iota + 1
	resp2Error
	resp2Integer
	resp2BulkString
	resp2NullBulk
	resp2Array
)

// resp2Value is one duplicate-preserving value backed by the decoder buffer.
type resp2Value struct {
	kind    resp2Kind
	bytes   []byte
	integer int64
	values  []resp2Value
	owner   *resp2Decoder
}

// resp2Decoder owns one exact bounded protected reply buffer.
type resp2Decoder struct {
	reader  io.Reader
	buffer  [maximumAuditReplyBytes]byte
	used    int
	values  int
	cleared bool
}

// newRESP2Decoder constructs one bounded streaming decoder.
func newRESP2Decoder(reader io.Reader) *resp2Decoder {
	return &resp2Decoder{reader: reader}
}

// decode reads exactly one supported root response.
func (d *resp2Decoder) decode() (resp2Value, error) {
	if d == nil || nilInterface(d.reader) {
		return resp2Value{}, d.inconsistent()
	}
	value, err := d.decodeValue(0)
	if err == nil {
		value.owner = d
	}
	return value, err
}

// clear erases decoder-owned or synthetic value bytes recursively.
func (v *resp2Value) clear() {
	if v == nil {
		return
	}
	if v.owner != nil {
		v.owner.clear()
		v.owner = nil
	} else {
		clear(v.bytes)
		for index := range v.values {
			v.values[index].clear()
		}
	}
	v.bytes = nil
	v.values = nil
}

// decodeValue decodes one value while enforcing aggregate and depth bounds.
func (d *resp2Decoder) decodeValue(containerDepth int) (resp2Value, error) {
	if d.values >= maximumRESPValues {
		return resp2Value{}, d.inconsistent()
	}
	d.values++
	prefix, err := d.readByte()
	if err != nil {
		return resp2Value{}, err
	}
	switch prefix {
	case '+':
		value, lineErr := d.readControlLine()
		return resp2Value{kind: resp2SimpleString, bytes: value}, lineErr
	case '-':
		value, lineErr := d.readControlLine()
		return resp2Value{kind: resp2Error, bytes: value}, lineErr
	case ':':
		value, lineErr := d.readControlLine()
		if lineErr != nil {
			return resp2Value{}, lineErr
		}
		integer, valid := parseRESPInteger(value)
		if !valid {
			return resp2Value{}, d.inconsistent()
		}
		return resp2Value{kind: resp2Integer, integer: integer}, nil
	case '$':
		return d.decodeBulkString()
	case '*':
		return d.decodeArray(containerDepth)
	default:
		return resp2Value{}, d.inconsistent()
	}
}

// decodeBulkString rejects hostile declarations before reading payload bytes.
func (d *resp2Decoder) decodeBulkString() (resp2Value, error) {
	lengthBytes, err := d.readControlLine()
	if err != nil {
		return resp2Value{}, err
	}
	length, null, valid := parseRESPCount(lengthBytes, true)
	if !valid {
		return resp2Value{}, d.inconsistent()
	}
	if null {
		return resp2Value{kind: resp2NullBulk}, nil
	}
	if length > maximumAuditReplyBytes-d.used-2 {
		return resp2Value{}, d.inconsistent()
	}
	start := d.used
	if err := d.readExact(length); err != nil {
		return resp2Value{}, err
	}
	value := d.buffer[start:d.used]
	if err := d.readCRLF(); err != nil {
		return resp2Value{}, err
	}
	return resp2Value{kind: resp2BulkString, bytes: value}, nil
}

// decodeArray rejects aggregate and nesting declarations before child reads.
func (d *resp2Decoder) decodeArray(containerDepth int) (resp2Value, error) {
	lengthBytes, err := d.readControlLine()
	if err != nil {
		return resp2Value{}, err
	}
	length, _, valid := parseRESPCount(lengthBytes, false)
	if !valid || containerDepth >= maximumRESPDepth ||
		length > maximumRESPValues-d.values {
		return resp2Value{}, d.inconsistent()
	}
	values := make([]resp2Value, length)
	for index := range length {
		value, valueErr := d.decodeValue(containerDepth + 1)
		if valueErr != nil {
			return resp2Value{}, valueErr
		}
		values[index] = value
	}
	return resp2Value{kind: resp2Array, values: values}, nil
}

// readControlLine reads one exact CRLF-terminated line after its prefix.
func (d *resp2Decoder) readControlLine() ([]byte, error) {
	start := d.used
	for {
		value, err := d.readByte()
		if err != nil {
			return nil, err
		}
		if value == '\n' {
			return nil, d.inconsistent()
		}
		if value != '\r' {
			if d.used-start > maximumRESPLineBytes {
				return nil, d.inconsistent()
			}
			continue
		}
		next, err := d.readByte()
		if err != nil {
			return nil, err
		}
		if next != '\n' {
			return nil, d.inconsistent()
		}
		return d.buffer[start : d.used-2], nil
	}
}

// readByte reads exactly one byte without permitting buffered over-read.
func (d *resp2Decoder) readByte() (byte, error) {
	if d.used >= len(d.buffer) {
		return 0, d.inconsistent()
	}
	if _, err := io.ReadFull(d.reader, d.buffer[d.used:d.used+1]); err != nil {
		return 0, d.readFailure(err)
	}
	value := d.buffer[d.used]
	d.used++
	return value, nil
}

// readExact reads one declared payload only after its complete bound is proven.
func (d *resp2Decoder) readExact(length int) error {
	if length < 0 || length > len(d.buffer)-d.used {
		return d.inconsistent()
	}
	if length == 0 {
		return nil
	}
	if _, err := io.ReadFull(d.reader, d.buffer[d.used:d.used+length]); err != nil {
		return d.readFailure(err)
	}
	d.used += length
	return nil
}

// readCRLF consumes one exact bulk-string terminator.
func (d *resp2Decoder) readCRLF() error {
	first, err := d.readByte()
	if err != nil {
		return err
	}
	second, err := d.readByte()
	if err != nil {
		return err
	}
	if first != '\r' || second != '\n' {
		return d.inconsistent()
	}
	return nil
}

// readFailure separates wire truncation from a live transport failure.
func (d *resp2Decoder) readFailure(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return d.inconsistent()
	}
	return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
}

// clear erases every protected byte retained by the decoder.
func (d *resp2Decoder) clear() {
	if d == nil {
		return
	}
	clear(d.buffer[:])
	d.cleared = true
}

// bufferCleared proves test-visible idempotent protected-buffer erasure.
func (d *resp2Decoder) bufferCleared() bool {
	if d == nil || !d.cleared {
		return false
	}
	for _, value := range d.buffer {
		if value != 0 {
			return false
		}
	}
	return true
}

// inconsistent constructs one bounded decoder failure.
func (*resp2Decoder) inconsistent() error {
	return dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
}

// parseRESPInteger parses one canonical signed RESP integer.
func parseRESPInteger(value []byte) (int64, bool) {
	if len(value) == 0 || value[0] == '+' {
		return 0, false
	}
	negative := value[0] == '-'
	digits := value
	maximum := uint64(1<<63 - 1)
	if negative {
		if len(value) == 1 {
			return 0, false
		}
		digits = value[1:]
		maximum = uint64(1 << 63)
	}
	magnitude, valid := parseRESPUnsigned(digits, maximum)
	if !valid || negative && magnitude == 0 {
		return 0, false
	}
	if !negative {
		return int64(magnitude), true
	}
	if magnitude == uint64(1)<<63 {
		return -1 << 63, true
	}
	return -int64(magnitude), true
}

// parseRESPCount parses one canonical nonnegative length or exact null bulk.
func parseRESPCount(value []byte, allowNull bool) (int, bool, bool) {
	if allowNull && len(value) == 2 && value[0] == '-' && value[1] == '1' {
		return 0, true, true
	}
	count, valid := parseRESPUnsigned(value, maximumAuditReplyBytes)
	if !valid {
		return 0, false, false
	}
	return int(count), false, true
}

// parseRESPUnsigned parses one bounded canonical unsigned decimal in owned bytes.
func parseRESPUnsigned(value []byte, maximum uint64) (uint64, bool) {
	if len(value) == 0 || len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	parsed := uint64(0)
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
		digit := uint64(character - '0')
		if parsed > maximum/10 ||
			parsed == maximum/10 && digit > maximum%10 {
			return 0, false
		}
		parsed = parsed*10 + digit
	}
	return parsed, true
}

// validateRESP2InfoLineLengths validates exact CRLF and the per-line cap.
func validateRESP2InfoLineLengths(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	start := 0
	for index := range payload {
		switch payload[index] {
		case '\n':
			if index == 0 || payload[index-1] != '\r' ||
				index-1-start > maximumRESPLineBytes {
				return dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
			}
			start = index + 1
		case '\r':
			if index+1 >= len(payload) || payload[index+1] != '\n' {
				return dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
			}
		}
	}
	if start != len(payload) {
		return dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
	}
	return nil
}
