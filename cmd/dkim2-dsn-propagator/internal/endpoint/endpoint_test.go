package endpoint

import "testing"

// TestCanonicalOrigins proves that only literal loopback origins are admitted.
func TestCanonicalOrigins(t *testing.T) {
	httpCases := map[string]bool{
		"http://127.0.0.1:8080":          true,
		"http://[::1]:8080":              true,
		"http://localhost:8080":          false,
		"http://127.0.0.1:8080/":         false,
		"http://127.0.0.1:8080?a=b":      false,
		"http://user@127.0.0.1:8080":     false,
		"https://127.0.0.1:8080":         false,
		"http://10.0.0.1:8080":           false,
		"http://127.0.0.1":               false,
		"http://[::ffff:127.0.0.1]:8080": false,
		"smtp://127.0.0.1:8080":          false,
	}
	for value, want := range httpCases {
		if got := IsCanonicalLoopbackHTTPURL(value); got != want {
			t.Fatalf("http %q: got %t want %t", value, got, want)
		}
	}
	smtpCases := map[string]bool{
		"smtp://127.0.0.1:10025":  true,
		"smtp://[::1]:10025":      true,
		"smtp://mail.example:25":  false,
		"http://127.0.0.1:10025":  false,
		"smtp://127.0.0.1:10025/": false,
	}
	for value, want := range smtpCases {
		if got := IsCanonicalLoopbackSMTPURL(value); got != want {
			t.Fatalf("smtp %q: got %t want %t", value, got, want)
		}
	}
}

// TestAuthority proves the literal authority extraction and its refusals.
func TestAuthority(t *testing.T) {
	authority, ok := Authority("smtp://127.0.0.1:10025")
	if !ok || authority != "127.0.0.1:10025" {
		t.Fatalf("authority: %q ok=%t", authority, ok)
	}
	if _, ok := Authority("smtp://mail.example:25"); ok {
		t.Fatal("hostname authority admitted")
	}
}
