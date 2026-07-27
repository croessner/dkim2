package signingstore

import "encoding/pem"

// decodePEMBlock delegates one strict PEM block decode.
func decodePEMBlock(encoded []byte) (*pem.Block, []byte) {
	return pem.Decode(encoded)
}
