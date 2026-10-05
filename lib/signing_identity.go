package dkim2

// SigningIdentity returns the domain and Unix timestamp of the newly generated
// signature on a proved unrestricted result. It excludes inherited signatures
// and fails closed for zero or incoherent results. Restricted results do not
// expose this accessor; their existing release boundaries remain unchanged.
func (m UnrestrictedSignedMessage) SigningIdentity() (domain string, timestamp uint64, err error) {
	if !m.Valid() {
		return "", 0, newSigningError(SigningErrorInvalidRequest)
	}
	domain, timestamp, err = m.message.SigningIdentity()
	if err != nil {
		return "", 0, mapOperationError(err)
	}
	return domain, timestamp, nil
}
