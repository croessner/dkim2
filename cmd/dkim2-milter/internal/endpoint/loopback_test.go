package endpoint

import "testing"

// TestIsCanonicalLoopbackHTTPURLFreezesExactOrigins rejects parser-equivalent drift.
func TestIsCanonicalLoopbackHTTPURLFreezesExactOrigins(t *testing.T) {
	for _, value := range []string{
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		if !IsCanonicalLoopbackHTTPURL(value) {
			t.Fatalf("canonical loopback origin %q was rejected", value)
		}
	}
	for _, value := range []string{
		"http://127.0.0.1:8080?",
		"http://127.0.0.1:8080#",
		"http://127.0.0.1:8080/%23",
		"http://127.0.0.1:8080/",
		"http://127.0.0.1:08080",
		"http://127.0.0.1",
		"http://localhost:8080",
		"http://[::ffff:127.0.0.1]:8080",
		"https://127.0.0.1:8080",
	} {
		if IsCanonicalLoopbackHTTPURL(value) {
			t.Fatalf("noncanonical loopback origin %q was accepted", value)
		}
	}
}

// TestIsCanonicalLoopbackAuthorityFreezesExactAuthorities rejects mapped and named hosts.
func TestIsCanonicalLoopbackAuthorityFreezesExactAuthorities(t *testing.T) {
	for _, value := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if !IsCanonicalLoopbackAuthority(value) {
			t.Fatalf("canonical loopback authority %q was rejected", value)
		}
	}
	for _, value := range []string{
		"localhost:9090", "127.0.0.1:09090", "[::ffff:127.0.0.1]:9090",
	} {
		if IsCanonicalLoopbackAuthority(value) {
			t.Fatalf("noncanonical loopback authority %q was accepted", value)
		}
	}
}
