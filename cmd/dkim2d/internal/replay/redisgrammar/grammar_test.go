package redisgrammar

import (
	"strconv"
	"strings"
	"testing"
)

// shortAddress is the smallest valid single-label endpoint.
const shortAddress = "a:1"

// TestValidAddressMatrix pins the shared host:port grammar, including
// underscore container names and the refused non-canonical forms.
func TestValidAddressMatrix(t *testing.T) {
	accepted := []string{
		"127.0.0.1:6379", "[2001:db8::1]:6379", "redis.internal:6379",
		"mailstack_valkey:6379", shortAddress, "redis-1.svc_x.cluster.local:65535",
	}
	for _, input := range accepted {
		if !ValidAddress(input) {
			t.Fatalf("ValidAddress(%q) refused", input)
		}
	}
	rejected := []string{
		"", "a.internal", "a.internal:", ":6379", "a.internal:0", "a.internal:65536",
		"a.internal:06379", "a.internal:+1", "Redis.internal:6379", "redis.internal.:6379",
		"-redis.internal:6379", "redis-.internal:6379", "redis..internal:6379",
		"999.1.1.1:6379", "10.0.0:6379", "0.0.0.0:6379", "[::]:6379", "224.0.0.1:6379",
		"[fe80::1%en0]:6379", "[::ffff:192.0.2.1]:6379", "[2001:DB8::1]:6379",
		"2001:db8::1:6379", "redis{tag}.internal:6379", "user@redis.internal:6379",
		"redis://redis.internal:6379", strings.Repeat("a", 64) + ".internal:6379",
	}
	for _, input := range rejected {
		if ValidAddress(input) {
			t.Fatalf("ValidAddress(%q) accepted", input)
		}
	}
	element := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 60) + ":10"
	if len(element) != MaxAddressBytes || !ValidAddress(element) || ValidAddress(element+"0") {
		t.Fatal("address byte bound drifted")
	}
}

// TestValidAddressListBounds pins count, duplicate, and emptiness rules.
func TestValidAddressListBounds(t *testing.T) {
	list := func(count int) []string {
		values := make([]string, count)
		for index := range values {
			values[index] = "node-" + strconv.Itoa(index) + ".internal:6379"
		}
		return values
	}
	for _, maximum := range []int{MaxSentinelAddresses, MaxClusterAddresses} {
		if !ValidAddressList(list(maximum), maximum) || ValidAddressList(list(maximum+1), maximum) {
			t.Fatalf("list bound %d drifted", maximum)
		}
	}
	if ValidAddressList(nil, 1) || ValidAddressList([]string{shortAddress, shortAddress}, 2) ||
		ValidAddressList([]string{shortAddress, ""}, 2) {
		t.Fatal("empty, duplicate, or blank list accepted")
	}
}

// TestValidIdentifierMatrix pins usernames, master names, key prefixes, and
// server names at their exact boundaries.
func TestValidIdentifierMatrix(t *testing.T) {
	visible := strings.Repeat("u", MaxIdentifierBytes-4) + "@!~%"
	if !ValidUsername(visible) || ValidUsername(visible+"x") || ValidUsername("") ||
		ValidUsername("a b") || ValidUsername("a\x7f") {
		t.Fatal("username grammar drifted")
	}
	if !ValidMasterName(strings.Repeat("M", MaxIdentifierBytes)) || !ValidMasterName("my_master.1-a") ||
		ValidMasterName(strings.Repeat("M", MaxIdentifierBytes+1)) || ValidMasterName("a:b") ||
		ValidMasterName("") || ValidMasterName("a@b") {
		t.Fatal("master-name grammar drifted")
	}
	if !ValidKeyPrefix("") || !ValidKeyPrefix(strings.Repeat("K", MaxKeyPrefixBytes)) ||
		!ValidKeyPrefix("tenant_A.1:x-") || ValidKeyPrefix(strings.Repeat("K", MaxKeyPrefixBytes+1)) ||
		ValidKeyPrefix("{tag}") || ValidKeyPrefix("a b") {
		t.Fatal("key-prefix grammar drifted")
	}
	for _, accepted := range []string{"localhost", "replay.example", "10.0.0.1", "2001:db8::1", "replay"} {
		if !ValidServerName(accepted) {
			t.Fatalf("ValidServerName(%q) refused", accepted)
		}
	}
	for _, rejected := range []string{"", "Replay.example", "a..b", "-a.example", "mail_x.example", "fe80::1%en0", "a.example."} {
		if ValidServerName(rejected) {
			t.Fatalf("ValidServerName(%q) accepted", rejected)
		}
	}
}
