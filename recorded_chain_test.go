package dkim2_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	dkim2 "github.com/croessner/dkim2"
)

// recordedChainRaw returns an unsigned two-hop message whose list hop rewrote Subject and
// appended a footer, recorded in Message-Instance 2.
func recordedChainRaw(recipeJSON string) []byte {
	hashSet := "sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + ":" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	sets := "rsa.test:rsa-sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 128))
	hop := func(sequence, instance int, domain string) string {
		return fmt.Sprintf("DKIM2-Signature: i=%d; m=%d; t=1698790400; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=%s; s=%s;\r\n", sequence, instance, domain, sets)
	}
	return []byte("From: sender@example.test\r\nSubject: [list] Hello\r\n" +
		"Message-Instance: m=1; h=" + hashSet + ";\r\n" +
		"Message-Instance: m=2; h=" + hashSet + "; r=" + base64.StdEncoding.EncodeToString([]byte(recipeJSON)) + ";\r\n" +
		hop(1, 1, "example.test") + hop(2, 2, "lists.example.test") +
		"\r\nbody line\r\n-- \r\nlist footer\r\n")
}

// TestDescribeRecordedChainProjectsRecordedRecipes locks the public provider-free description.
func TestDescribeRecordedChainProjectsRecordedRecipes(t *testing.T) {
	hops, err := dkim2.DescribeRecordedChain(recordedChainRaw(`{"h":{"subject":[{"d":["Hello"]}]},"b":[{"c":[1,1]}]}`))
	if err != nil || len(hops) != 2 {
		t.Fatalf("DescribeRecordedChain() = %d hops, %v", len(hops), err)
	}
	if hops[0].SignerDomain() != "example.test" || hops[0].RecipeMode() != "unchanged" || hops[0].Recipe().ChangeCount() != 0 {
		t.Fatalf("origin = %q %q", hops[0].SignerDomain(), hops[0].RecipeMode())
	}
	list := hops[1]
	if list.SignerDomain() != "lists.example.test" || list.Sequence() != 2 || list.MessageInstance() != 2 || !list.IntroducesInstance() ||
		list.RecipeMode() != "applied" || list.Recipe().BodyMode() != "steps" ||
		!slices.Equal(list.Recipe().AffectedHeaders(), []string{"subject"}) ||
		!slices.Equal(list.Recipe().ChangeClasses(), []string{"body.rewrite", "header.rewrite"}) {
		t.Fatalf("list hop = %q seq %d m=%d %q %q %v %v", list.SignerDomain(), list.Sequence(), list.MessageInstance(),
			list.RecipeMode(), list.Recipe().BodyMode(), list.Recipe().AffectedHeaders(), list.Recipe().ChangeClasses())
	}
	headers := list.Recipe().AffectedHeaders()
	headers[0] = "mutated"
	if list.Recipe().AffectedHeaders()[0] != "subject" {
		t.Fatal("recipe headers were mutable through the accessor")
	}
	if text := fmt.Sprintf("%v %+v %#v %s", list, list, list, list); strings.Contains(text, "example") {
		t.Fatalf("formatting exposed message facts: %s", text)
	}
}

// TestDescribeRecordedChainWithoutProtocolFields returns no hops and no error.
func TestDescribeRecordedChainWithoutProtocolFields(t *testing.T) {
	hops, err := dkim2.DescribeRecordedChain([]byte("From: a@example.test\r\nSubject: plain\r\n\r\nbody\r\n"))
	if err != nil || hops != nil {
		t.Fatalf("DescribeRecordedChain(plain) = %d hops, %v", len(hops), err)
	}
}

// TestDescribeRecordedChainFailsClosed refuses malformed input instead of describing part of it.
func TestDescribeRecordedChainFailsClosed(t *testing.T) {
	cases := map[string][]byte{
		"malformed recipe": recordedChainRaw(`{"h":`),
		"sequence gap":     []byte(strings.Replace(string(recordedChainRaw(`{"b":null}`)), "i=2;", "i=3;", 1)),
		"not a message":    []byte("no header colon\r\n\r\n"),
		"oversized":        make([]byte, dkim2.HardMaxRawMessageBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			hops, err := dkim2.DescribeRecordedChain(raw)
			var apiErr *dkim2.APIError
			if hops != nil || err == nil || !errors.As(err, &apiErr) || apiErr.Code() != dkim2.APIErrorCodeInvalidRequest {
				t.Fatalf("DescribeRecordedChain() = %d hops, %v; want invalid_request", len(hops), err)
			}
		})
	}
}
