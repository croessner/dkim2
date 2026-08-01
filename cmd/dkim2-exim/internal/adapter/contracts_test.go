package adapter

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestContractsCloneWithoutAliasing proves every accessor preserves ownership.
func TestContractsCloneWithoutAliasing(t *testing.T) {
	buildID := []byte(strings.Repeat("a", buildIDBytes))
	peer := []byte("192.0.2.1")
	helo := []byte("mail.example")
	protocol := []byte("esmtps")
	mailFrom := []byte("incoming")
	recipients := [][]byte{[]byte("recipient")}
	headers := [][]byte{[]byte("Subject: value\n")}
	body := []byte("body\n")
	request, err := NewLocalScanRequest(
		buildID, SessionSMTP, peer, 25, helo, protocol, mailFrom,
		recipients, headers, body,
	)
	if err != nil {
		t.Fatal("valid request construction failed")
	}
	for _, value := range [][]byte{
		buildID, peer, helo, protocol, mailFrom, recipients[0], headers[0], body,
	} {
		value[0] ^= 1
	}
	if string(request.BuildID()) != strings.Repeat("a", buildIDBytes) ||
		request.Session() != SessionSMTP || string(request.Peer()) != "192.0.2.1" ||
		request.PeerPort() != 25 || string(request.HELO()) != "mail.example" ||
		string(request.ReceivedProtocol()) != "esmtps" ||
		string(request.MailFrom()) != "incoming" ||
		string(request.Recipients()[0]) != "recipient" ||
		string(request.Headers()[0]) != "Subject: value\n" ||
		string(request.Body()) != "body\n" {
		t.Fatal("local-scan evidence clone aliases caller data")
	}
	returned := [][]byte{
		request.BuildID(), request.Peer(), request.HELO(),
		request.ReceivedProtocol(), request.MailFrom(),
		request.Recipients()[0], request.Headers()[0], request.Body(),
	}
	for _, value := range returned {
		value[0] ^= 1
	}
	if string(request.MailFrom()) != "incoming" ||
		string(request.Body()) != "body\n" {
		t.Fatal("local-scan accessor aliases owned evidence")
	}

	incoming, err := NewIncomingEvidence(
		[]byte("old"), [][]byte{[]byte("old-r")}, SessionSMTP,
	)
	if err != nil {
		t.Fatal("incoming evidence construction failed")
	}
	outgoing, err := NewOutgoingEnvelope([]byte("new"), []byte("new-r"))
	if err != nil {
		t.Fatal("outgoing evidence construction failed")
	}
	filterInput := []byte("Subject: test\n\nmessage\n")
	filter, err := NewReviseRequest(filterInput, outgoing, incoming)
	if err != nil {
		t.Fatal("revision construction failed")
	}
	filterMessage := filter.Message()
	filterOutgoing := filter.Outgoing()
	filterIncoming, ok := filter.Incoming()
	if filter.Operation() != FilterRevise || !ok ||
		string(filterOutgoing.MailFrom()) != "new" ||
		string(filterOutgoing.Recipient()) != "new-r" ||
		string(filterIncoming.MailFrom()) != "<old>" ||
		string(filterIncoming.Recipients()[0]) != "<old-r>" ||
		filterIncoming.Session() != SessionSMTP {
		t.Fatal("filter request did not preserve distinct envelope ownership")
	}
	filterMessage[0] ^= 1
	if string(filter.Message()) != "Subject: test\n\nmessage\n" {
		t.Fatal("filter message accessor aliases owned evidence")
	}
}

// TestLocalScanRequestRejectsInvalidStructure proves exact scalar and header grammar.
func TestLocalScanRequestRejectsInvalidStructure(t *testing.T) {
	validBuildID := []byte(strings.Repeat("a", buildIDBytes))
	valid := func(
		buildID, peer, helo, protocol, mailFrom []byte,
		recipients, headers [][]byte,
		peerPort uint16,
	) error {
		_, err := NewLocalScanRequest(
			buildID, SessionSMTP, peer, peerPort, helo, protocol,
			mailFrom, recipients, headers, nil,
		)
		return err
	}
	cases := []struct {
		name       string
		buildID    []byte
		peer       []byte
		peerPort   uint16
		helo       []byte
		protocol   []byte
		mailFrom   []byte
		recipients [][]byte
		headers    [][]byte
	}{
		{"short build id", validBuildID[:buildIDBytes-1], nil, 0, nil, nil, nil, [][]byte{nil}, nil},
		{"uppercase build id", []byte(strings.Repeat("A", buildIDBytes)), nil, 0, nil, nil, nil, [][]byte{nil}, nil},
		{"nonhex build id", append([]byte(strings.Repeat("a", buildIDBytes-1)), 'g'), nil, 0, nil, nil, nil, [][]byte{nil}, nil},
		{"peer without port", validBuildID, []byte("peer"), 0, nil, nil, nil, [][]byte{nil}, nil},
		{"port without peer", validBuildID, nil, 25, nil, nil, nil, [][]byte{nil}, nil},
		{"peer framing", validBuildID, []byte("peer\n"), 25, nil, nil, nil, [][]byte{nil}, nil},
		{"helo framing", validBuildID, nil, 0, []byte("helo\r"), nil, nil, [][]byte{nil}, nil},
		{"protocol framing", validBuildID, nil, 0, nil, []byte("smtp\x00"), nil, [][]byte{nil}, nil},
		{"sender framing", validBuildID, nil, 0, nil, nil, []byte("a\nb"), [][]byte{nil}, nil},
		{"recipient framing", validBuildID, nil, 0, nil, nil, nil, [][]byte{[]byte("a\rb")}, nil},
		{"header missing LF", validBuildID, nil, 0, nil, nil, nil, [][]byte{nil}, [][]byte{[]byte("Subject: x")}},
		{"header bare CR", validBuildID, nil, 0, nil, nil, nil, [][]byte{nil}, [][]byte{[]byte("Subject: x\r\n")}},
		{"header NUL", validBuildID, nil, 0, nil, nil, nil, [][]byte{nil}, [][]byte{[]byte("X:\x00\n")}},
		{"illegal header continuation", validBuildID, nil, 0, nil, nil, nil, [][]byte{nil}, [][]byte{[]byte("X: a\nY: b\n")}},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			if err := valid(
				current.buildID, current.peer, current.helo, current.protocol,
				current.mailFrom, current.recipients, current.headers,
				current.peerPort,
			); err == nil {
				t.Fatal("invalid local-scan structure succeeded")
			}
		})
	}
	if err := valid(
		validBuildID, []byte("peer"), []byte("hélo"), []byte("smtp"),
		[]byte("mü@example"), [][]byte{[]byte("rü@example")},
		[][]byte{[]byte("Subject: x\n folded\n")}, 25,
	); err != nil {
		t.Fatal("valid inbound UTF-8 and folded header failed")
	}
}

// TestLocalScanRequestLimits proves exact semantic limits and one-over rejection.
func TestLocalScanRequestLimits(t *testing.T) {
	buildID := []byte(strings.Repeat("a", buildIDBytes))
	makeRequest := func(
		peer, helo, protocol, mailFrom []byte,
		recipients, headers [][]byte,
		body []byte,
	) error {
		_, err := NewLocalScanRequest(
			buildID, SessionSMTP, peer, 25, helo, protocol,
			mailFrom, recipients, headers, body,
		)
		return err
	}
	exactHeader := append(
		[]byte("X:"),
		bytes.Repeat([]byte{'a'}, maxHeaderFieldBytes-3)...,
	)
	exactHeader = append(exactHeader, '\n')
	exactBody := make([]byte, maxMessageBytes-len(exactHeader)-1)
	if err := makeRequest(
		bytes.Repeat([]byte{'p'}, maxPeerBytes),
		bytes.Repeat([]byte{'h'}, maxHELOBytes),
		bytes.Repeat([]byte{'s'}, maxReceivedProtocolBytes),
		bytes.Repeat([]byte{'m'}, maxEnvelopeBytes),
		[][]byte{bytes.Repeat([]byte{'r'}, maxEnvelopeBytes)},
		[][]byte{exactHeader}, exactBody,
	); err != nil {
		t.Fatal("exact local-scan limits failed")
	}
	exactAggregate := make([][]byte, maxHeaderAggregateBytes/maxHeaderFieldBytes)
	for index := range exactAggregate {
		exactAggregate[index] = bytes.Clone(exactHeader)
	}
	if err := makeRequest(
		[]byte("p"), nil, nil, nil, [][]byte{nil}, exactAggregate, nil,
	); err != nil {
		t.Fatal("exact aggregate header limit failed")
	}
	aggregateOneOver := append(
		append([][]byte(nil), exactAggregate...),
		[]byte("X\n"),
	)
	oneOverCases := []struct {
		name       string
		peer       []byte
		helo       []byte
		protocol   []byte
		mailFrom   []byte
		recipients [][]byte
		headers    [][]byte
		body       []byte
	}{
		{"peer", bytes.Repeat([]byte{'p'}, maxPeerBytes+1), nil, nil, nil, [][]byte{nil}, nil, nil},
		{"helo", []byte("p"), bytes.Repeat([]byte{'h'}, maxHELOBytes+1), nil, nil, [][]byte{nil}, nil, nil},
		{"protocol", []byte("p"), nil, bytes.Repeat([]byte{'s'}, maxReceivedProtocolBytes+1), nil, [][]byte{nil}, nil, nil},
		{"sender", []byte("p"), nil, nil, bytes.Repeat([]byte{'m'}, maxEnvelopeBytes+1), [][]byte{nil}, nil, nil},
		{"recipient", []byte("p"), nil, nil, nil, [][]byte{bytes.Repeat([]byte{'r'}, maxEnvelopeBytes+1)}, nil, nil},
		{"recipient count", []byte("p"), nil, nil, nil, make([][]byte, maxRecipients+1), nil, nil},
		{"header field", []byte("p"), nil, nil, nil, [][]byte{nil}, [][]byte{append(bytes.Repeat([]byte{'x'}, maxHeaderFieldBytes), '\n')}, nil},
		{"header count", []byte("p"), nil, nil, nil, [][]byte{nil}, make([][]byte, maxHeaders+1), nil},
		{"header aggregate", []byte("p"), nil, nil, nil, [][]byte{nil}, aggregateOneOver, nil},
		{"message", []byte("p"), nil, nil, nil, [][]byte{nil}, nil, make([]byte, maxMessageBytes)},
	}
	for _, current := range oneOverCases {
		t.Run(current.name, func(t *testing.T) {
			if err := makeRequest(
				current.peer, current.helo, current.protocol, current.mailFrom,
				current.recipients, current.headers, current.body,
			); err == nil {
				t.Fatal("one-over local-scan limit succeeded")
			}
		})
	}
}

// TestEnvelopeContractsPreserveInboundUTF8AndRejectOutboundUTF8 proves authority rules.
func TestEnvelopeContractsPreserveInboundUTF8AndRejectOutboundUTF8(t *testing.T) {
	incoming, err := NewIncomingEvidence(
		[]byte("mü@example"), [][]byte{[]byte("rü@example")}, SessionSMTP,
	)
	if err != nil || string(incoming.MailFrom()) != "<mü@example>" ||
		string(incoming.Recipients()[0]) != "<rü@example>" {
		t.Fatal("inbound SMTPUTF8 evidence failed")
	}
	validCases := []struct {
		sender    []byte
		recipient []byte
	}{
		{nil, []byte("bounce@example")},
		{[]byte("sender@example"), []byte("recipient@example")},
		{[]byte{1}, []byte{0x7f}},
	}
	for _, current := range validCases {
		if _, err := NewOutgoingEnvelope(current.sender, current.recipient); err != nil {
			t.Fatal("valid ASCII outgoing envelope failed")
		}
	}
	invalidCases := []struct {
		sender    []byte
		recipient []byte
	}{
		{nil, nil},
		{[]byte("mü@example"), []byte("recipient@example")},
		{[]byte("sender@example"), []byte("rü@example")},
		{[]byte("sender\nexample"), []byte("recipient@example")},
		{[]byte("sender@example"), []byte("recipient\x00example")},
		{bytes.Repeat([]byte{'s'}, maxEnvelopeBytes+1), []byte("recipient@example")},
		{nil, bytes.Repeat([]byte{'r'}, maxEnvelopeBytes+1)},
	}
	for _, current := range invalidCases {
		if _, err := NewOutgoingEnvelope(current.sender, current.recipient); err == nil {
			t.Fatal("invalid outgoing envelope succeeded")
		}
	}
}

// TestCanonicalEximPathRejectsAmbiguousFraming proves one shared Exim-to-SMTP
// path conversion accepts bare and bracketed EAI paths but rejects ambiguity.
func TestCanonicalEximPathRejectsAmbiguousFraming(t *testing.T) {
	validCases := []struct {
		value   []byte
		reverse bool
		want    string
	}{
		{[]byte("sender@example.test"), true, "<sender@example.test>"},
		{[]byte("<sender@example.test>"), true, "<sender@example.test>"},
		{nil, true, "<>"},
		{[]byte("mü@example.test"), false, "<mü@example.test>"},
	}
	for _, current := range validCases {
		got, err := CanonicalEximPath(current.value, current.reverse)
		if err != nil || string(got) != current.want {
			t.Fatal("valid Exim path was not canonicalized")
		}
	}
	invalidCases := [][]byte{
		nil, []byte("<sender@example.test"), []byte("sender@example.test>"),
		[]byte("<sender<@example.test>"), []byte("sender\r@example.test"),
	}
	for _, current := range invalidCases {
		if _, err := CanonicalEximPath(current, false); err == nil {
			t.Fatal("ambiguous Exim path was accepted")
		}
	}
}

// TestFilterRequestRequiresProvedTransportFraming closes fidelity before mapping.
func TestFilterRequestRequiresProvedTransportFraming(t *testing.T) {
	outgoing, err := NewOutgoingEnvelope(nil, []byte("recipient@example"))
	if err != nil {
		t.Fatal("valid outgoing envelope failed")
	}
	valid := [][]byte{
		[]byte("Subject: value\n"),
		[]byte("Subject: value"),
		[]byte("Subject: value\n folded\n\n"),
		[]byte("Subject: value\n\nbinary\x00body\r\n"),
		[]byte("Subject: value\n\nbody-without-LF"),
	}
	for _, message := range valid {
		request, constructErr := NewSignRequest(message, outgoing)
		if constructErr != nil {
			t.Fatal("valid completed transport message failed")
		}
		complete := request.Message()
		if complete[len(complete)-1] != '\n' {
			t.Fatal("transport completion did not own one final LF")
		}
	}
	invalid := [][]byte{
		nil,
		[]byte("not-a-header\n"),
		[]byte(" Subject: continuation\n"),
		[]byte("Subject : invalid-name\n"),
		[]byte("Subject: bare CR\r\n\nbody\n"),
		[]byte("Subject: NUL\x00\n\nbody\n"),
		[]byte("Subject: illegal\nnot-a-header\n\nbody"),
	}
	for _, message := range invalid {
		if _, err = NewSignRequest(message, outgoing); err == nil {
			t.Fatal("ambiguous transport message succeeded")
		}
	}
	if _, err = NewSignRequest(make([]byte, maxMessageBytes+1), outgoing); err == nil {
		t.Fatal("one-over transport message succeeded")
	}
	exact := make([]byte, maxMessageBytes)
	copy(exact, "X: x\n\n")
	exact[len(exact)-1] = '\n'
	if _, err = NewSignRequest(exact, outgoing); err != nil {
		t.Fatal("exact completed transport message failed")
	}
	exact[len(exact)-1] = 'x'
	if _, err = NewSignRequest(exact, outgoing); err == nil {
		t.Fatal("maximum input requiring LF growth succeeded")
	}
	request, exactErr := NewSignRequest(exact[:len(exact)-1], outgoing)
	if exactErr != nil {
		t.Fatal("one-short transport input did not normalize to the exact limit")
	}
	complete := request.Message()
	if len(complete) != maxMessageBytes || complete[maxMessageBytes-1] != '\n' {
		t.Fatal("one-short transport normalization was not exact")
	}
}

// TestFilterRequestCountsUnterminatedFinalHeader proves Exim's virtual final
// LF cannot reset cumulative header-count admission.
func TestFilterRequestCountsUnterminatedFinalHeader(t *testing.T) {
	outgoing, err := NewOutgoingEnvelope(nil, []byte("recipient@example"))
	if err != nil {
		t.Fatal("valid outgoing envelope failed")
	}
	message := bytes.Repeat([]byte("X:\n"), maxHeaders)
	message = append(message, "X:"...)
	if _, err = NewSignRequest(message, outgoing); err == nil {
		t.Fatal("unterminated final header bypassed cumulative header limits")
	}
}

// TestActionContractClosesNamesValuesAndLimits proves exact append-only admission.
func TestActionContractClosesNamesValuesAndLimits(t *testing.T) {
	for _, name := range []string{
		headerAuthenticationResults, headerMessageInstance, headerDKIM2Signature,
	} {
		if _, err := NewAction(
			ActionAddHeader, name, strings.Repeat("x", maxActionValueBytes),
		); err != nil {
			t.Fatal("exact maximum action value failed")
		}
	}
	invalid := []struct {
		kind  ActionKind
		name  string
		value string
	}{
		{0, headerDKIM2Signature, " x"},
		{ActionAddHeader, "Subject", " x"},
		{ActionAddHeader, "dkim2-signature", " x"},
		{ActionAddHeader, headerDKIM2Signature, ""},
		{ActionAddHeader, headerDKIM2Signature, " x\n"},
		{ActionAddHeader, headerDKIM2Signature, " x\r"},
		{ActionAddHeader, headerDKIM2Signature, " x\x00"},
		{ActionAddHeader, headerDKIM2Signature, strings.Repeat("x", maxActionValueBytes+1)},
	}
	for _, current := range invalid {
		if _, err := NewAction(current.kind, current.name, current.value); err == nil {
			t.Fatal("invalid action succeeded")
		}
	}
}

// TestPlanOperationMatrices proves each operation owns only its exact mutations.
func TestPlanOperationMatrices(t *testing.T) {
	auth, _ := NewAction(ActionAddHeader, headerAuthenticationResults, "mx; dkim2=pass")
	instance, _ := NewAction(ActionAddHeader, headerMessageInstance, " value")
	signature, _ := NewAction(ActionAddHeader, headerDKIM2Signature, "\tvalue")
	for result := ResultPass; result <= ResultTemperror; result++ {
		for disposition := DispositionAccept; disposition <= DispositionTempfail; disposition++ {
			plan, err := NewPlan(result, disposition, nil)
			if err != nil || plan.Operation() != OperationProcess {
				t.Fatalf("valid process plan failed for result %d and disposition %d", result, disposition)
			}
			if disposition == DispositionAccept {
				if _, err := NewPlan(result, disposition, []Action{auth}); err != nil {
					t.Fatalf("valid accepting process report failed for result %d", result)
				}
			}
		}
	}
	validFilter := []struct {
		operation   FilterOperation
		owner       Operation
		result      Result
		disposition Disposition
		actions     []Action
	}{
		{FilterSign, OperationSign, ResultPass, DispositionAccept, []Action{instance, signature}},
		{FilterSign, OperationSign, ResultPass, DispositionContinue, nil},
		{FilterSign, OperationSign, ResultNone, DispositionContinue, nil},
		{FilterSign, OperationSign, ResultFail, DispositionReject, nil},
		{FilterSign, OperationSign, ResultTemperror, DispositionTempfail, nil},
		{FilterRevise, OperationRevise, ResultPass, DispositionAccept, []Action{signature}},
		{FilterRevise, OperationRevise, ResultPass, DispositionAccept, []Action{instance, signature}},
	}
	for _, current := range validFilter {
		plan, err := NewFilterPlan(
			current.operation, current.result, current.disposition, current.actions,
		)
		if err != nil || plan.Operation() != current.owner {
			t.Fatal("valid filter plan failed")
		}
	}
	noWhitespace, _ := NewAction(ActionAddHeader, headerDKIM2Signature, "value")
	invalid := []struct {
		operation   FilterOperation
		result      Result
		disposition Disposition
		actions     []Action
	}{
		{0, ResultPass, DispositionAccept, nil},
		{FilterSign, ResultPass, DispositionAccept, nil},
		{FilterSign, ResultPass, DispositionAccept, []Action{signature, instance}},
		{FilterSign, ResultPass, DispositionAccept, []Action{instance, noWhitespace}},
		{FilterRevise, ResultPass, DispositionAccept, []Action{instance}},
		{FilterRevise, ResultFail, DispositionAccept, []Action{signature}},
		{FilterRevise, ResultFail, DispositionReject, []Action{signature}},
		{FilterRevise, ResultTemperror, DispositionContinue, nil},
	}
	for _, current := range invalid {
		if _, err := NewFilterPlan(
			current.operation, current.result, current.disposition, current.actions,
		); err == nil {
			t.Fatal("invalid filter plan succeeded")
		}
	}
	if _, err := NewPlan(
		ResultPass, DispositionAccept, []Action{signature},
	); err == nil {
		t.Fatal("process plan admitted filter-owned action")
	}
	if _, err := NewPlan(ResultFail, DispositionReject, []Action{auth}); err == nil {
		t.Fatal("process plan admitted a report action on a non-accepting outcome")
	}
}

// TestNotApplicablePlansRemainOperationBound proves bodyless applicability
// cannot authorize mutations, terminal outcomes, or a revise operation.
func TestNotApplicablePlansRemainOperationBound(t *testing.T) {
	process, err := NewPlan(ResultNone, DispositionContinue, nil)
	if err != nil || process.Operation() != OperationProcess ||
		process.Result() != ResultNone || process.Disposition() != DispositionContinue ||
		len(process.Actions()) != 0 {
		t.Fatal("valid process not-applicable plan failed")
	}
	sign, err := NewFilterPlan(FilterSign, ResultNone, DispositionContinue, nil)
	if err != nil || sign.Operation() != OperationSign ||
		sign.Result() != ResultNone || sign.Disposition() != DispositionContinue ||
		len(sign.Actions()) != 0 {
		t.Fatal("valid sign not-applicable plan failed")
	}
	action, _ := NewAction(ActionAddHeader, headerAuthenticationResults, "mx.example; dkim2=pass")
	for _, candidate := range []struct {
		operation   FilterOperation
		disposition Disposition
		actions     []Action
	}{
		{FilterSign, DispositionAccept, nil},
		{FilterSign, DispositionContinue, []Action{action}},
		{FilterRevise, DispositionContinue, nil},
	} {
		if _, candidateErr := NewFilterPlan(
			candidate.operation, ResultNone, candidate.disposition, candidate.actions,
		); candidateErr == nil {
			t.Fatal("invalid filter not-applicable plan succeeded")
		}
	}
	if _, err = NewPlan(ResultNone, DispositionAccept, nil); err == nil {
		t.Fatal("terminal process not-applicable plan succeeded")
	}
	if _, err = NewPlan(ResultNone, DispositionContinue, []Action{action}); err == nil {
		t.Fatal("mutating process not-applicable plan succeeded")
	}
}

// TestFilterPlansRetainTheirClosedOutcomeMatrix proves process flexibility cannot relax filters.
func TestFilterPlansRetainTheirClosedOutcomeMatrix(t *testing.T) {
	for result := ResultPass; result <= ResultTemperror; result++ {
		for disposition := DispositionAccept; disposition <= DispositionTempfail; disposition++ {
			if validFilterDisposition(result, disposition) {
				continue
			}
			if _, err := NewFilterPlan(FilterSign, result, disposition, nil); err == nil {
				t.Fatalf("filter admitted result %d and disposition %d outside its matrix", result, disposition)
			}
		}
	}
}

// TestZeroValuesCannotConcealRequiredState proves constructors reject forged emptiness.
func TestZeroValuesCannotConcealRequiredState(t *testing.T) {
	if _, err := NewSignRequest([]byte("Subject: x\n\nbody\n"), OutgoingEnvelope{}); err == nil {
		t.Fatal("zero outgoing envelope entered sign request")
	}
	outgoing, err := NewOutgoingEnvelope(nil, []byte("recipient@example"))
	if err != nil {
		t.Fatal("valid outgoing envelope failed")
	}
	if _, err := NewSignRequest(nil, outgoing); err == nil {
		t.Fatal("empty message entered sign request")
	}
	if _, err := NewReviseRequest(
		[]byte("Subject: x\n\nbody\n"), outgoing, IncomingEvidence{},
	); err == nil {
		t.Fatal("zero incoming evidence entered revise request")
	}
	if _, err := NewFilterPlan(
		0, ResultPass, DispositionAccept, nil,
	); err == nil {
		t.Fatal("zero operation entered action plan")
	}
}

// TestAdapterFailuresRemainClosedAndClassifiable proves immutable safe errors.
func TestAdapterFailuresRemainClosedAndClassifiable(t *testing.T) {
	for class := FailureInvalidRequest; class <= FailurePartialOutput; class++ {
		err := NewError(class)
		var typed *Error
		if !errors.As(err, &typed) || typed.Class() != class {
			t.Fatal("adapter failure class was not externally classifiable")
		}
	}
	var zero *Error
	if zero.Class() != FailureInternal {
		t.Fatal("nil error did not fail closed")
	}
	invalid := NewError(FailureClass(255))
	var typed *Error
	if !errors.As(invalid, &typed) || typed.Class() != FailureInternal {
		t.Fatal("unknown failure class did not collapse to internal")
	}
}

// TestSensitiveContractsRejectSerializationAndFormatting proves privacy for all shapes.
func TestSensitiveContractsRejectSerializationAndFormatting(t *testing.T) {
	marker := "toxic-marker"
	buildID := []byte(strings.Repeat("a", buildIDBytes))
	request, _ := NewLocalScanRequest(
		buildID, SessionSMTP, nil, 0, nil, nil, []byte(marker),
		[][]byte{[]byte(marker)}, [][]byte{[]byte("X: " + marker + "\n")},
		[]byte(marker),
	)
	incoming, _ := NewIncomingEvidence(
		[]byte(marker), [][]byte{[]byte(marker)}, SessionSMTP,
	)
	outgoing, _ := NewOutgoingEnvelope([]byte(marker), []byte(marker))
	filter, _ := NewReviseRequest(
		[]byte("Subject: "+marker+"\n\n"+marker+"\n"), outgoing, incoming,
	)
	action, _ := NewAction(ActionAddHeader, headerDKIM2Signature, " "+marker)
	plan, _ := NewFilterPlan(
		FilterRevise, ResultPass, DispositionAccept, []Action{action},
	)
	values := []any{
		&Error{class: FailureContract}, Error{},
		request, incoming, outgoing, filter, action, plan,
		LocalScanRequest{}, IncomingEvidence{}, OutgoingEnvelope{},
		FilterRequest{}, Action{}, Plan{},
	}
	for _, value := range values {
		output := fmt.Sprintf("%v %+v %#v %s %q %x %X", value, value, value, value, value, value, value)
		if strings.Contains(output, marker) {
			t.Fatal("formatting exposed protected evidence")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("JSON serialization of protected contract succeeded")
		}
		text, ok := value.(encoding.TextMarshaler)
		if ok {
			if _, err := text.MarshalText(); err == nil {
				t.Fatal("text serialization of protected contract succeeded")
			}
		}
	}
}
