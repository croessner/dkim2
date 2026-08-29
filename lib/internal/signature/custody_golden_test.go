package signature

import (
	"encoding/json"
	"os"
	"testing"
)

type custodyGoldenFile struct {
	Draft        string              `json:"draft"`
	CustodyCases []custodyGoldenCase `json:"custody_cases"`
}

type custodyGoldenCase struct {
	Name       string                   `json:"name"`
	WantStatus CustodyStatus            `json:"want_status"`
	WantError  ErrorCode                `json:"want_error"`
	Signatures []custodyGoldenSignature `json:"signatures"`
}

type custodyGoldenSignature struct {
	Sequence   uint64   `json:"sequence"`
	Instance   uint64   `json:"instance"`
	Domain     string   `json:"domain"`
	MailFrom   string   `json:"mail_from"`
	Recipients []string `json:"recipients"`
	NextDomain string   `json:"next_domain"`
}

// TestDraft06CustodyGoldenVectors locks immutable adjacent custody semantics.
func TestDraft06CustodyGoldenVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/vectors/draft-ietf-dkim-dkim2-spec-06/custody-crypto-golden.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var golden custodyGoldenFile
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if golden.Draft != "draft-ietf-dkim-dkim2-spec-06" || len(golden.CustodyCases) == 0 {
		t.Fatal("custody golden file has wrong or empty draft contract")
	}
	for _, test := range golden.CustodyCases {
		t.Run(test.Name, func(t *testing.T) {
			signatures := make([]Signature, len(test.Signatures))
			for index, vector := range test.Signatures {
				if vector.NextDomain != "" {
					signatures[index] = nextDomainCustodySignature(vector.Sequence, vector.Domain, vector.NextDomain)
				} else {
					signatures[index] = ordinaryCustodySignature(vector.Sequence, vector.Domain, vector.MailFrom, vector.Recipients...)
				}
				signatures[index].instanceNumber = vector.Instance
			}
			result, validationErr := ValidateCustody(signatures, CustodyLimits{})
			if test.WantError != "" {
				if !IsErrorCode(validationErr, test.WantError) {
					t.Fatalf("ValidateCustody() code=%s, want %s", custodyTestCode(validationErr), test.WantError)
				}
				return
			}
			if validationErr != nil || result.Status() != test.WantStatus {
				t.Fatalf("ValidateCustody() code=%s status=%s, want %s", custodyTestCode(validationErr), result.Status(), test.WantStatus)
			}
		})
	}
}
