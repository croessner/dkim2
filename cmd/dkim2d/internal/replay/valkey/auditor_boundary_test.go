package valkey

import (
	"bytes"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
)

// TestSecurityAuditorACLTopLevelPermutations proves pair and flag order independence.
func TestSecurityAuditorACLTopLevelPermutations(t *testing.T) {
	canonical := aclAuditValue(
		"-@all +ping +set",
		"~dkim2:replay:v1:*",
		"",
		"db=0",
		[]resp2Value{bulkAuditValue("sanitize-payload"), bulkAuditValue("on")},
		nil,
		[]string{syntheticPasswordHash},
	)
	const pairCount = 7
	order := make([]int, pairCount)
	for index := range order {
		order[index] = index
	}

	permutationCount := 0
	var visit func(int)
	visit = func(position int) {
		if position == pairCount {
			values := make([]resp2Value, 0, len(canonical.values))
			for _, pair := range order {
				values = append(values, canonical.values[pair*2], canonical.values[pair*2+1])
			}
			if validation := validateACLGetUser(arrayAuditValue(values...)); validation != auditAccepted {
				t.Fatalf("permutation %v validation = %d, want accepted", order, validation)
			}
			permutationCount++
			return
		}
		for index := position; index < pairCount; index++ {
			order[position], order[index] = order[index], order[position]
			visit(position + 1)
			order[position], order[index] = order[index], order[position]
		}
	}
	visit(0)

	if permutationCount != 5_040 {
		t.Fatalf("permutation count = %d, want 5040", permutationCount)
	}
}

// TestSecurityAuditorRejectsUnsortedACLDatabases proves source-impossible order fails closed.
func TestSecurityAuditorRejectsUnsortedACLDatabases(t *testing.T) {
	value := aclAuditValue(
		"-@all +ping +set",
		"~dkim2:replay:v1:*",
		"",
		"db=1,0",
		canonicalFlags(),
		nil,
		[]string{syntheticPasswordHash},
	)
	if validation := validateACLGetUser(value); validation != auditMalformed {
		t.Fatalf("validation = %d, want malformed", validation)
	}
	assertAuditValueCode(
		t,
		7,
		value,
		auditPhaseRuntime,
		dkim2.ReplayErrorInconsistent,
	)
}

// TestSecurityAuditorINFONameLengthBoundaries freezes section and field name caps.
func TestSecurityAuditorINFONameLengthBoundaries(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		payload string
		valid   bool
	}{
		{
			name: "section 64",
			payload: "# " + strings.Repeat("S", 64) + "\r\nignored:1\r\n" +
				"# Memory\r\nused_memory:16777216\r\n",
			valid: true,
		},
		{
			name: "section 65",
			payload: "# " + strings.Repeat("S", 65) + "\r\nignored:1\r\n" +
				"# Memory\r\nused_memory:16777216\r\n",
		},
		{
			name: "field 128",
			payload: "# Memory\r\n" + strings.Repeat("f", 128) +
				":ignored\r\nused_memory:16777216\r\n",
			valid: true,
		},
		{
			name: "field 129",
			payload: "# Memory\r\n" + strings.Repeat("f", 129) +
				":ignored\r\nused_memory:16777216\r\n",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			value := infoAuditValue(testCase.payload)
			if testCase.valid {
				assertAuditValueSuccess(t, 3, value)
				return
			}
			assertAuditValueCode(
				t,
				3,
				value,
				auditPhaseRuntime,
				dkim2.ReplayErrorInconsistent,
			)
		})
	}
}

// TestSecurityAuditorROLEHostAndSlaveStateBoundaries freezes official ROLE shapes.
func TestSecurityAuditorROLEHostAndSlaveStateBoundaries(t *testing.T) {
	for _, testCase := range []struct {
		name string
		host string
		want auditValidation
	}{
		{name: "master host 255", host: strings.Repeat("h", 255), want: auditPolicyMismatch},
		{name: "master host 256", host: strings.Repeat("h", 256), want: auditMalformed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			value := masterRoleWithReplica(testCase.host, "6379", "40")
			if validation := validateRole(value, &auditSnapshot{}); validation != testCase.want {
				t.Fatalf("validation = %d, want %d", validation, testCase.want)
			}
		})
	}

	for _, state := range []string{
		"handshake",
		"none",
		"connect",
		"connecting",
		"sync",
		"connected",
		auditUnknownToken,
	} {
		t.Run("slave state "+state, func(t *testing.T) {
			value := arrayAuditValue(
				bulkAuditValue("slave"),
				bulkAuditValue("arbitrary-master-host"),
				integerAuditValue(6379),
				bulkAuditValue(state),
				integerAuditValue(42),
			)
			if validation := validateRole(value, &auditSnapshot{}); validation != auditPolicyMismatch {
				t.Fatalf("validation = %d, want policy mismatch", validation)
			}
		})
	}
}

// TestSecurityAuditorMaxmemoryPolicyTokenBoundaries freezes its forward-compatible grammar.
func TestSecurityAuditorMaxmemoryPolicyTokenBoundaries(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		token string
		want  auditValidation
	}{
		{name: "length 1", token: "a", want: auditPolicyMismatch},
		{name: "length 32", token: strings.Repeat("a", 32), want: auditPolicyMismatch},
		{name: "length 33", token: strings.Repeat("a", 33), want: auditMalformed},
		{name: "uppercase", token: "Noeviction", want: auditMalformed},
		{name: "underscore", token: "no_eviction", want: auditMalformed},
		{name: "space", token: "no eviction", want: auditMalformed},
		{name: "nul", token: "no\x00eviction", want: auditMalformed},
		{name: testNameNonASCII, token: "noeviction\xff", want: auditMalformed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			value := configAuditValue(
				testCase.token,
				"67108864",
				"0",
				"30",
				"60 1",
				"no",
				"no",
			)
			if validation := validateConfig(
				value,
				validSecurityAuditPolicy(),
				&auditSnapshot{},
			); validation != testCase.want {
				t.Fatalf("validation = %d, want %d", validation, testCase.want)
			}
		})
	}
}

// TestSecurityAuditorErrorTokenExtractorBoundaries freezes bounded exact-token parsing.
func TestSecurityAuditorErrorTokenExtractorBoundaries(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		value []byte
		kind  auditErrorKind
		valid bool
	}{
		{name: "length 1", value: []byte("A"), kind: auditErrorUnknown, valid: true},
		{name: "length 32", value: []byte(strings.Repeat("A", 32)), kind: auditErrorUnknown, valid: true},
		{name: "length 33", value: []byte(strings.Repeat("A", 33)), kind: auditErrorUnknown},
		{name: "exact mapped", value: []byte(serverKindOOM), kind: auditErrorMapped, valid: true},
		{name: "mapped prefix collision", value: []byte(serverKindOOM + "X"), kind: auditErrorUnknown, valid: true},
		{name: "exact busy", value: []byte(serverKindBUSY), kind: auditErrorBusy, valid: true},
		{name: "busy prefix collision", value: []byte(serverKindBUSY + "X"), kind: auditErrorUnknown, valid: true},
		{name: "underscore and digit grammar", value: []byte("A_B9"), kind: auditErrorUnknown, valid: true},
		{name: testNameEmpty, value: nil, kind: auditErrorUnknown},
		{name: "leading space", value: []byte(" OOM"), kind: auditErrorUnknown},
		{name: "lowercase first", value: []byte("oOM"), kind: auditErrorUnknown},
		{name: "lowercase later", value: []byte("OoM"), kind: auditErrorUnknown},
		{name: "hyphen", value: []byte("NO-AUTH"), kind: auditErrorUnknown},
		{name: "tab delimiter", value: []byte("OOM\tsuffix"), kind: auditErrorUnknown},
		{name: "line-feed delimiter", value: []byte("OOM\nsuffix"), kind: auditErrorUnknown},
		{name: testNameNonASCII, value: []byte{'O', 'O', 'M', 0xff}, kind: auditErrorUnknown},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			kind, valid := leadingAuditErrorKind(testCase.value)
			if kind != testCase.kind || valid != testCase.valid {
				t.Fatalf("extractor = (%d,%t), want (%d,%t)",
					kind, valid, testCase.kind, testCase.valid)
			}
		})
	}

	for index, suffix := range [][]byte{
		{},
		[]byte("ordinary"),
		[]byte("OOM prefix collision must not refine"),
		[]byte{0, '\t', '\r', '\n', 0xff},
		[]byte(strings.Repeat("x", 128)),
	} {
		value := append([]byte(serverKindOOM+" "), suffix...)
		kind, valid := leadingAuditErrorKind(value)
		if kind != auditErrorMapped || !valid {
			t.Fatalf("suffix case %d extractor = (%d,%t), want mapped true",
				index, kind, valid)
		}
	}
}

// TestSecurityAuditorCommandDescriptorLengthBoundary freezes the exact source envelope cap.
func TestSecurityAuditorCommandDescriptorLengthBoundary(t *testing.T) {
	const prefix = "-@all "
	atCap := append([]byte(prefix), bytes.Repeat([]byte{'a'}, maximumAuditReplyBytes-len(prefix))...)
	if len(atCap) != maximumAuditReplyBytes || !validCommandDescriptor(atCap) {
		t.Fatal("exact-cap closed command descriptor was rejected")
	}
	overCap := append(append([]byte(nil), atCap...), 'a')
	if len(overCap) != maximumAuditReplyBytes+1 || validCommandDescriptor(overCap) {
		t.Fatal("cap-plus-one command descriptor was accepted")
	}
	clear(atCap)
	clear(overCap)
}
