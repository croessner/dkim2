package inbound

// clearHeaders erases temporary immutable header accessor copies.
func clearHeaders(headers [][]byte) {
	for index := range headers {
		clear(headers[index])
	}
}
