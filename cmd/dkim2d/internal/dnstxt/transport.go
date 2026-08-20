// Package dnstxt provides the daemon-owned TTL-aware DNS TXT transport.
package dnstxt

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/croessner/dkim2"
	"github.com/miekg/dns"
)

const (
	defaultResolverConfig = "/etc/resolv.conf"
	maximumCNAMEHops      = 8
	maximumResolverCount  = 3
	maximumAttempts       = 5
)

type messageExchanger interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type transportState struct {
	udp, tcp messageExchanger
	servers  []string
	attempts int
}

type ttlEvidence struct {
	seconds uint32
	set     bool
}

type answerIndex struct {
	txtByOwner   map[string][]*dns.TXT
	cnameByOwner map[string]*dns.CNAME
}

// Transport resolves absolute TXT owners while retaining DNS TTL provenance.
type Transport struct {
	state *transportState
}

// New constructs a TTL-aware transport from the system resolver configuration.
func New() (*Transport, error) {
	configuration, err := dns.ClientConfigFromFile(defaultResolverConfig)
	if err != nil || len(configuration.Servers) == 0 || configuration.Port == "" {
		return nil, dkim2.NewPermanentProviderError()
	}
	serverCount := min(len(configuration.Servers), maximumResolverCount)
	servers := make([]string, 0, serverCount)
	for _, server := range configuration.Servers[:serverCount] {
		if net.ParseIP(server) == nil {
			return nil, dkim2.NewPermanentProviderError()
		}
		servers = append(servers, net.JoinHostPort(server, configuration.Port))
	}
	attempts := configuration.Attempts
	if attempts < 1 {
		attempts = 1
	}
	attempts = min(attempts, maximumAttempts)
	return newTransport(servers, attempts, &dns.Client{Net: "udp"}, &dns.Client{Net: "tcp"})
}

// newTransport constructs a deterministic transport around bounded injected exchangers.
func newTransport(servers []string, attempts int, udp, tcp messageExchanger) (*Transport, error) {
	if len(servers) == 0 || attempts < 1 || udp == nil || tcp == nil {
		return nil, dkim2.NewPermanentProviderError()
	}
	for _, server := range servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return nil, dkim2.NewPermanentProviderError()
		}
	}
	return &Transport{state: &transportState{
		udp: udp, tcp: tcp, servers: slices.Clone(servers), attempts: attempts,
	}}, nil
}

// LookupTXT resolves one absolute owner and preserves positive or negative TTL evidence.
func (t *Transport) LookupTXT(ctx context.Context, absoluteName string) (dkim2.TXTLookupResult, error) {
	if t == nil || t.state == nil || ctx == nil || !dns.IsFqdn(absoluteName) {
		return dkim2.TXTLookupResult{}, dkim2.NewPermanentProviderError()
	}
	if err := ctx.Err(); err != nil {
		return dkim2.TXTLookupResult{}, err
	}
	owner := strings.ToLower(absoluteName)
	visited := make(map[string]struct{}, maximumCNAMEHops)
	var chainTTL ttlEvidence
	for range maximumCNAMEHops {
		if _, duplicate := visited[owner]; duplicate {
			return dkim2.TXTLookupResult{}, dkim2.NewPermanentProviderError()
		}
		visited[owner] = struct{}{}
		response, err := t.exchange(ctx, owner)
		if err != nil {
			return dkim2.TXTLookupResult{}, err
		}
		result, next, answerTTL, done, err := interpretResponse(response, owner)
		if err != nil {
			return dkim2.TXTLookupResult{}, err
		}
		chainTTL.includeEvidence(answerTTL)
		if done {
			return withBoundedResultTTL(result, chainTTL)
		}
		owner = next
	}
	return dkim2.TXTLookupResult{}, dkim2.NewPermanentProviderError()
}

// exchange performs bounded resolver failover and TCP retry for truncated UDP answers.
func (t *Transport) exchange(ctx context.Context, owner string) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(owner, dns.TypeTXT)
	query.SetEdns0(1232, false)
	for range t.state.attempts {
		for _, server := range t.state.servers {
			response, _, err := t.state.udp.ExchangeContext(ctx, query.Copy(), server)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
				continue
			}
			if response == nil {
				continue
			}
			if response.Truncated {
				response, _, err = t.state.tcp.ExchangeContext(ctx, query.Copy(), server)
				if err != nil || response == nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						return nil, ctxErr
					}
					continue
				}
			}
			if response.Truncated || response.Rcode == dns.RcodeServerFailure || response.Rcode == dns.RcodeRefused {
				continue
			}
			return response, nil
		}
	}
	return nil, dkim2.NewTemporaryProviderError()
}

// interpretResponse classifies one DNS response and returns an optional CNAME continuation.
func interpretResponse(response *dns.Msg, queriedOwner string) (dkim2.TXTLookupResult, string, ttlEvidence, bool, error) {
	absence, err := classifyResponse(response, queriedOwner)
	if err != nil {
		return dkim2.TXTLookupResult{}, "", ttlEvidence{}, true, err
	}
	index, err := indexResponseAnswers(response)
	if err != nil {
		return dkim2.TXTLookupResult{}, "", ttlEvidence{}, true, err
	}
	return walkResponseAnswers(response, queriedOwner, absence, index)
}

// classifyResponse validates response identity and maps its bounded DNS outcome class.
func classifyResponse(response *dns.Msg, queriedOwner string) (dkim2.TXTAbsenceClass, error) {
	if response == nil || !response.Response || len(response.Question) != 1 ||
		response.Question[0].Qtype != dns.TypeTXT || response.Question[0].Qclass != dns.ClassINET ||
		!strings.EqualFold(response.Question[0].Name, queriedOwner) {
		return "", dkim2.NewPermanentProviderError()
	}
	switch response.Rcode {
	case dns.RcodeNameError:
		return dkim2.TXTAbsenceNXDOMAIN, nil
	case dns.RcodeSuccess:
		return dkim2.TXTAbsenceNODATA, nil
	case dns.RcodeServerFailure, dns.RcodeRefused:
		return "", dkim2.NewTemporaryProviderError()
	default:
		return "", dkim2.NewPermanentProviderError()
	}
}

// indexResponseAnswers groups only bounded IN TXT and CNAME records by canonical owner.
func indexResponseAnswers(response *dns.Msg) (answerIndex, error) {
	index := answerIndex{
		txtByOwner:   make(map[string][]*dns.TXT),
		cnameByOwner: make(map[string]*dns.CNAME),
	}
	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.TXT:
			if record.Hdr.Class != dns.ClassINET {
				continue
			}
			owner := strings.ToLower(record.Hdr.Name)
			index.txtByOwner[owner] = append(index.txtByOwner[owner], record)
		case *dns.CNAME:
			if record.Hdr.Class != dns.ClassINET {
				continue
			}
			owner := strings.ToLower(record.Hdr.Name)
			target := strings.ToLower(record.Target)
			if _, valid := dns.IsDomainName(target); !valid || !dns.IsFqdn(target) {
				return answerIndex{}, dkim2.NewPermanentProviderError()
			}
			if existing := index.cnameByOwner[owner]; existing != nil && !strings.EqualFold(existing.Target, target) {
				return answerIndex{}, dkim2.NewPermanentProviderError()
			}
			index.cnameByOwner[owner] = record
		}
	}
	return index, nil
}

// walkResponseAnswers follows the response-local CNAME chain and selects only owned TXT records.
func walkResponseAnswers(
	response *dns.Msg,
	queriedOwner string,
	absence dkim2.TXTAbsenceClass,
	index answerIndex,
) (dkim2.TXTLookupResult, string, ttlEvidence, bool, error) {
	owner := strings.ToLower(queriedOwner)
	visited := make(map[string]struct{}, maximumCNAMEHops)
	var answerTTL ttlEvidence
	for range maximumCNAMEHops {
		if _, duplicate := visited[owner]; duplicate {
			return dkim2.TXTLookupResult{}, "", ttlEvidence{}, true, dkim2.NewPermanentProviderError()
		}
		visited[owner] = struct{}{}
		payloadRecords := index.txtByOwner[owner]
		cname := index.cnameByOwner[owner]
		if len(payloadRecords) > 0 && cname != nil {
			return dkim2.TXTLookupResult{}, "", ttlEvidence{}, true, dkim2.NewPermanentProviderError()
		}
		if len(payloadRecords) > 0 {
			return foundResult(response.Rcode, payloadRecords, answerTTL)
		}
		if cname == nil {
			break
		}
		answerTTL.include(cname.Hdr.Ttl)
		owner = strings.ToLower(cname.Target)
	}
	if len(visited) == maximumCNAMEHops && index.cnameByOwner[owner] != nil {
		return dkim2.TXTLookupResult{}, "", ttlEvidence{}, true, dkim2.NewPermanentProviderError()
	}
	negativeTTL := negativeTTLEvidence(response, owner)
	if response.Rcode == dns.RcodeNameError || negativeTTL.set {
		result, err := dkim2.NewAbsentTXTLookupResult(absence, negativeTTL.duration(), dkim2.DNSSECStatusUnavailable)
		return result, "", answerTTL, true, err
	}
	if owner != strings.ToLower(queriedOwner) {
		return dkim2.TXTLookupResult{}, owner, answerTTL, false, nil
	}
	result, err := dkim2.NewAbsentTXTLookupResult(dkim2.TXTAbsenceNODATA, 0, dkim2.DNSSECStatusUnavailable)
	return result, "", ttlEvidence{}, true, err
}

// foundResult joins TXT character strings without merging distinct resource records.
func foundResult(rcode int, records []*dns.TXT, chainTTL ttlEvidence) (dkim2.TXTLookupResult, string, ttlEvidence, bool, error) {
	if rcode != dns.RcodeSuccess {
		return dkim2.TXTLookupResult{}, "", ttlEvidence{}, true, dkim2.NewPermanentProviderError()
	}
	payloads := make([][]byte, len(records))
	for index, record := range records {
		payloads[index] = []byte(strings.Join(record.Txt, ""))
		chainTTL.include(record.Hdr.Ttl)
	}
	if len(payloads) > 1 {
		result, err := dkim2.NewAmbiguousTXTLookupResult(len(payloads), chainTTL.duration(), dkim2.DNSSECStatusUnavailable)
		return result, "", chainTTL, true, err
	}
	result, err := dkim2.NewFoundTXTLookupResult(payloads, chainTTL.duration(), dkim2.DNSSECStatusUnavailable)
	return result, "", chainTTL, true, err
}

// withBoundedResultTTL applies the shortest CNAME-chain TTL to a terminal result.
func withBoundedResultTTL(result dkim2.TXTLookupResult, chainTTL ttlEvidence) (dkim2.TXTLookupResult, error) {
	if result.IsZero() || !chainTTL.set {
		return result, nil
	}
	switch result.Status() {
	case dkim2.TXTLookupStatusFound:
		if result.PositiveTTL() > 0 && chainTTL.duration() >= result.PositiveTTL() {
			return result, nil
		}
		records := result.Records()
		payloads := make([][]byte, len(records))
		for index := range records {
			payloads[index] = records[index].Payload()
		}
		if result.RecordCount() > 1 {
			return dkim2.NewAmbiguousTXTLookupResult(result.RecordCount(), chainTTL.duration(), result.DNSSECStatus())
		}
		return dkim2.NewFoundTXTLookupResult(payloads, chainTTL.duration(), result.DNSSECStatus())
	case dkim2.TXTLookupStatusAbsent:
		if result.NegativeTTL() == 0 || chainTTL.duration() >= result.NegativeTTL() {
			return result, nil
		}
		return dkim2.NewAbsentTXTLookupResult(result.Absence(), chainTTL.duration(), result.DNSSECStatus())
	default:
		return dkim2.TXTLookupResult{}, dkim2.NewPermanentProviderError()
	}
}

// negativeTTLEvidence derives the RFC 2308 lifetime from an enclosing authority SOA.
func negativeTTLEvidence(response *dns.Msg, owner string) ttlEvidence {
	var ttl ttlEvidence
	for _, authority := range response.Ns {
		soa, ok := authority.(*dns.SOA)
		if !ok || soa.Hdr.Class != dns.ClassINET || !dns.IsSubDomain(strings.ToLower(soa.Hdr.Name), owner) {
			continue
		}
		candidate := soa.Hdr.Ttl
		if soa.Minttl < candidate {
			candidate = soa.Minttl
		}
		ttl.include(candidate)
	}
	return ttl
}

// include retains the shortest observed TTL, including an explicit zero.
func (t *ttlEvidence) include(value uint32) {
	if t != nil && (!t.set || value < t.seconds) {
		t.seconds, t.set = value, true
	}
}

// includeEvidence merges another optional TTL observation.
func (t *ttlEvidence) includeEvidence(value ttlEvidence) {
	if value.set {
		t.include(value.seconds)
	}
}

// duration converts the DNS uint32-second range without overflow.
func (t ttlEvidence) duration() time.Duration {
	if !t.set {
		return 0
	}
	return time.Duration(t.seconds) * time.Second
}

// String returns a constant secret-safe transport summary.
func (*Transport) String() string { return "dkim2d.dnstxt.Transport{redacted}" }

// GoString returns the constant secret-safe transport representation.
func (t *Transport) GoString() string { return t.String() }

// Format prevents resolver endpoints and query state from reaching formatting sinks.
func (*Transport) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2d.dnstxt.Transport{redacted}")
}
