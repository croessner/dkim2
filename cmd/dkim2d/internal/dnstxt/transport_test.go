package dnstxt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/miekg/dns"
)

const (
	testKeyOwner       = "key.example.test."
	testPayload        = "p=QQ=="
	testResolverServer = "127.0.0.1:53"
)

type exchangeFunc func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)

// ExchangeContext delegates one test exchange to the configured function.
func (f exchangeFunc) ExchangeContext(ctx context.Context, message *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	return f(ctx, message, server)
}

// TestTransportPreservesShortestPositiveTTLAndTXTChunks proves TTL-aware CNAME handling.
func TestTransportPreservesShortestPositiveTTLAndTXTChunks(t *testing.T) {
	calls := 0
	exchange := exchangeFunc(func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		calls++
		response := new(dns.Msg)
		response.SetReply(query)
		switch query.Question[0].Name {
		case "selector._domainkey.example.test.":
			response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 600}, Target: testKeyOwner}}
		case testKeyOwner:
			response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=DKIM1; ", testPayload}}}
		default:
			t.Fatal("unexpected DNS owner")
		}
		return response, 0, nil
	})
	transport := mustTransport(t, exchange, exchange)
	result, err := transport.LookupTXT(context.Background(), "selector._domainkey.example.test.")
	if err != nil || result.Status() != dkim2.TXTLookupStatusFound || result.PositiveTTL() != 5*time.Minute || calls != 2 {
		t.Fatalf("LookupTXT() status=%q ttl=%s calls=%d error=%v", result.Status(), result.PositiveTTL(), calls, err)
	}
	if records := result.Records(); len(records) != 1 || string(records[0].Payload()) != "v=DKIM1; p=QQ==" {
		t.Fatal("TXT chunks or RR boundaries changed")
	}
}

// TestTransportValidatesAnswerOwnership proves unrelated TXT records cannot satisfy a lookup.
func TestTransportValidatesAnswerOwnership(t *testing.T) {
	exchange := fixedResponse(func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{
			&dns.TXT{Hdr: dns.RR_Header{Name: "unrelated.example.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 600}, Txt: []string{"p=toxic"}},
			&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: testKeyOwner},
			&dns.TXT{Hdr: dns.RR_Header{Name: testKeyOwner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120}, Txt: []string{testPayload}},
		}
		return response
	})
	result, err := mustTransport(t, exchange, exchange).LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.PositiveTTL() != 2*time.Minute {
		t.Fatalf("owned answer ttl=%s error=%v", result.PositiveTTL(), err)
	}
	if records := result.Records(); len(records) != 1 || string(records[0].Payload()) != testPayload {
		t.Fatal("unrelated TXT record was admitted")
	}
}

// TestTransportRejectsMismatchedQuestion proves resolver response substitution fails closed.
func TestTransportRejectsMismatchedQuestion(t *testing.T) {
	exchange := fixedResponse(func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Question[0].Name = "other.example.test."
		return response
	})
	_, err := mustTransport(t, exchange, exchange).LookupTXT(context.Background(), "s._domainkey.example.test.")
	if dkim2.ProviderErrorClassOf(err) != dkim2.ProviderErrorClassPermanent {
		t.Fatalf("mismatched question class=%q", dkim2.ProviderErrorClassOf(err))
	}
}

// TestTransportRetainsExplicitZeroTTL proves zero never becomes invented cache provenance.
func TestTransportRetainsExplicitZeroTTL(t *testing.T) {
	exchange := fixedResponse(func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{testPayload}}}
		return response
	})
	result, err := mustTransport(t, exchange, exchange).LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.PositiveTTL() != 0 {
		t.Fatalf("zero TTL became %s, error=%v", result.PositiveTTL(), err)
	}
}

// TestTransportDerivesRFC2308NegativeTTL proves the SOA minimum rule and absence classes.
func TestTransportDerivesRFC2308NegativeTTL(t *testing.T) {
	for _, test := range []struct {
		name  string
		rcode int
		class dkim2.TXTAbsenceClass
	}{
		{name: "NXDOMAIN", rcode: dns.RcodeNameError, class: dkim2.TXTAbsenceNXDOMAIN},
		{name: "NODATA", rcode: dns.RcodeSuccess, class: dkim2.TXTAbsenceNODATA},
	} {
		t.Run(test.name, func(t *testing.T) {
			exchange := fixedResponse(func(query *dns.Msg) *dns.Msg {
				response := new(dns.Msg)
				response.SetReply(query)
				response.Rcode = test.rcode
				response.Ns = []dns.RR{
					&dns.SOA{Hdr: dns.RR_Header{Name: "unrelated.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1}, Minttl: 1},
					&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600}, Minttl: 120},
				}
				return response
			})
			result, err := mustTransport(t, exchange, exchange).LookupTXT(context.Background(), "s._domainkey.example.test.")
			if err != nil || result.Status() != dkim2.TXTLookupStatusAbsent || result.Absence() != test.class || result.NegativeTTL() != 2*time.Minute {
				t.Fatalf("LookupTXT() status=%q absence=%q ttl=%s error=%v", result.Status(), result.Absence(), result.NegativeTTL(), err)
			}
		})
	}
}

// TestTransportBoundsNegativeTTLByCNAME proves aliases cannot outlive their shortest TTL.
func TestTransportBoundsNegativeTTLByCNAME(t *testing.T) {
	exchange := fixedResponse(func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Rcode = dns.RcodeNameError
		response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "missing.example.test."}}
		response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600}, Minttl: 120}}
		return response
	})
	result, err := mustTransport(t, exchange, exchange).LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.Absence() != dkim2.TXTAbsenceNXDOMAIN || result.NegativeTTL() != 30*time.Second {
		t.Fatalf("CNAME NXDOMAIN absence=%q ttl=%s error=%v", result.Absence(), result.NegativeTTL(), err)
	}
}

// TestTransportRetriesTruncatedAnswersOverTCP proves bounded protocol fallback.
func TestTransportRetriesTruncatedAnswersOverTCP(t *testing.T) {
	udp := fixedResponse(func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Truncated = true
		return response
	})
	tcpCalls := 0
	tcp := exchangeFunc(func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		tcpCalls++
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{testPayload}}}
		return response, 0, nil
	})
	result, err := mustTransport(t, udp, tcp).LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.PositiveTTL() != time.Minute || tcpCalls != 1 {
		t.Fatalf("TCP fallback ttl=%s calls=%d error=%v", result.PositiveTTL(), tcpCalls, err)
	}
	truncatedTCP := fixedResponse(func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Truncated = true
		return response
	})
	if _, err := mustTransport(t, udp, truncatedTCP).LookupTXT(context.Background(), "s._domainkey.example.test."); dkim2.ProviderErrorClassOf(err) != dkim2.ProviderErrorClassTemporary {
		t.Fatalf("truncated TCP class=%q", dkim2.ProviderErrorClassOf(err))
	}
}

// TestTransportFailsOverTemporaryResolverResponses proves bounded server failover.
func TestTransportFailsOverTemporaryResolverResponses(t *testing.T) {
	calls := 0
	exchange := exchangeFunc(func(_ context.Context, query *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
		calls++
		response := new(dns.Msg)
		response.SetReply(query)
		if server == testResolverServer {
			response.Rcode = dns.RcodeServerFailure
			return response, 0, nil
		}
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{testPayload}}}
		return response, 0, nil
	})
	transport, err := newTransport([]string{testResolverServer, "127.0.0.2:53"}, 1, exchange, exchange)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if err != nil || result.PositiveTTL() != time.Minute || calls != 2 {
		t.Fatalf("resolver failover ttl=%s calls=%d error=%v", result.PositiveTTL(), calls, err)
	}
}

// TestTransportBoundsFailuresAndCNAMECycles proves typed fail-closed behavior.
func TestTransportBoundsFailuresAndCNAMECycles(t *testing.T) {
	temporary := exchangeFunc(func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error) {
		return nil, 0, errors.New("toxic resolver detail")
	})
	if _, err := mustTransport(t, temporary, temporary).LookupTXT(context.Background(), "s._domainkey.example.test."); dkim2.ProviderErrorClassOf(err) != dkim2.ProviderErrorClassTemporary {
		t.Fatalf("resolver failure class=%q", dkim2.ProviderErrorClassOf(err))
	}
	cycle := fixedResponse(func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: query.Question[0].Name}}
		return response
	})
	if _, err := mustTransport(t, cycle, cycle).LookupTXT(context.Background(), "s._domainkey.example.test."); dkim2.ProviderErrorClassOf(err) != dkim2.ProviderErrorClassPermanent {
		t.Fatalf("CNAME cycle class=%q", dkim2.ProviderErrorClassOf(err))
	}
}

// fixedResponse adapts one deterministic response builder into an exchanger.
func fixedResponse(build func(*dns.Msg) *dns.Msg) exchangeFunc {
	return func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		return build(query), 0, nil
	}
}

// mustTransport constructs one deterministic test transport.
func mustTransport(t *testing.T, udp, tcp messageExchanger) *Transport {
	t.Helper()
	transport, err := newTransport([]string{testResolverServer}, 1, udp, tcp)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}
