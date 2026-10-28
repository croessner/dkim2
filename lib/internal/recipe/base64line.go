package recipe

import "encoding/base64"

// decodeBase64Line decodes one Draft-08 Section 5 "base64-line": standard
// RFC 4648 alphabet, length a multiple of four, at most two trailing "="
// characters, zero pad bits, and no white space or line breaks anywhere. The
// alphabet is checked explicitly because the standard decoder silently skips
// CR and LF characters.
func decodeBase64Line(encoded []byte) ([]byte, bool) {
	if len(encoded)%4 != 0 {
		return nil, false
	}
	padding := 0
	for index, b := range encoded {
		switch {
		case b == '=':
			padding++
			if index < len(encoded)-2 {
				return nil, false
			}
		case padding > 0:
			return nil, false
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '+', b == '/':
		default:
			return nil, false
		}
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil {
		return nil, false
	}
	return decoded[:n], true
}

// encodeBase64Line renders decoded bytes as one canonical "base64-line".
func encodeBase64Line(decoded []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(decoded)))
	base64.StdEncoding.Encode(encoded, decoded)
	return encoded
}
