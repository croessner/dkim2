package ldap

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	goldap "github.com/go-ldap/ldap/v3"
)

// TerminalExecutor owns the dedicated LDAP closer bind and writes only
// immutable campaign-terminal entries below the fixed provider-owned container.
type TerminalExecutor struct{ connector AdministrationConnector }

// Close releases the dedicated closer connector after campaign completion.
func (e *TerminalExecutor) Close() {
	if e == nil || e.connector == nil {
		return
	}
	if closer, ok := e.connector.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	e.connector = nil
}

// NewTerminalExecutor validates one distinct closer connector before terminal writes.
func NewTerminalExecutor(connector AdministrationConnector) (*TerminalExecutor, error) {
	if connector == nil || !connector.AdministrationAuthority().Valid() {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	return &TerminalExecutor{connector: connector}, nil
}

// RecordTerminal adds one immutable terminal record and confirms exact readback.
func (e *TerminalExecutor) RecordTerminal(ctx context.Context, record datasourceadmin.TerminalRecord) error {
	if e == nil || e.connector == nil || ctx == nil || ctx.Err() != nil || !record.Valid() {
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	raw, err := e.connector.Connect(ctx)
	if err != nil || raw == nil {
		return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	client, ok := raw.(*goLDAPClient)
	if !ok {
		_ = raw.Close()
		return datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	defer client.Close() //nolint:errcheck
	if existing, present, err := client.readTerminal(ctx, record.Operation()); err != nil {
		return datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	} else if present {
		if terminalEqual(existing, record) {
			return nil
		}
		return datasourceadmin.NewError(datasourceadmin.CodeConflict)
	}
	if err := client.addTerminal(ctx, record); err != nil {
		client.Discard()
		return datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
	}
	readback, present, err := client.readTerminal(ctx, record.Operation())
	if err != nil || !present || !terminalEqual(readback, record) {
		return datasourceadmin.NewError(datasourceadmin.CodeReconcileRequired)
	}
	return nil
}

// ReadTerminal returns only exact parsed terminal evidence or proven absence.
func (e *TerminalExecutor) ReadTerminal(ctx context.Context, operation datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	if e == nil || e.connector == nil || ctx == nil || !operation.Initialized() {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	raw, err := e.connector.Connect(ctx)
	if err != nil || raw == nil {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	client, ok := raw.(*goLDAPClient)
	if !ok {
		_ = raw.Close()
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	defer client.Close() //nolint:errcheck
	record, present, err := client.readTerminal(ctx, operation)
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return record, present, nil
}

func (c *goLDAPClient) addTerminal(ctx context.Context, record datasourceadmin.TerminalRecord) error {
	operation := ""
	if err := record.Operation().WithValue(ctx, func(value string) error { operation = value; return nil }); err != nil {
		return err
	}
	digest := record.CandidateDigest().Bytes()
	defer clear(digest)
	request := goldap.NewAddRequest("dkim2OperationID="+goldap.EscapeDN(operation)+",ou=campaign-terminals,"+c.baseDN, nil)
	request.Attribute(attrObjectClass, []string{topObjectClass, "dkim2CampaignTerminal"})
	request.Attribute("cn", []string{"terminal-" + operation})
	request.Attribute(attrOperationID, []string{operation})
	request.Attribute(attrSchemaVersion, []string{record.CandidateSchema()})
	request.Attribute("dkim2SourceSchema", []string{record.SourceSchema()})
	request.Attribute("dkim2SourceGeneration", []string{strconv.FormatUint(record.SourceGeneration(), 10)})
	request.Attribute(attrGeneration, []string{strconv.FormatUint(record.CandidateGeneration(), 10)})
	request.Attribute("dkim2CurrentGeneration", []string{strconv.FormatUint(record.CurrentGeneration(), 10)})
	request.Attribute(attrCandidateDigest, []string{string(digest)})
	request.Attribute("dkim2TerminalState", []string{string(record.State())})
	request.Attribute("dkim2TerminalReason", []string{record.Reason()})
	request.Attribute("dkim2TerminalTime", []string{record.RecordedAt().Format("20060102150405.000000Z")})
	return c.call(ctx, func() error { return c.connection.Add(request) })
}

func (c *goLDAPClient) readTerminal(ctx context.Context, operation datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	value := ""
	if err := operation.WithValue(ctx, func(input string) error { value = input; return nil }); err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	request := goldap.NewSearchRequest("dkim2OperationID="+goldap.EscapeDN(value)+",ou=campaign-terminals,"+c.baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 2, 0, false, "(objectClass=dkim2CampaignTerminal)", []string{attrSchemaVersion, "dkim2SourceSchema", attrGeneration, attrCandidateDigest, "dkim2SourceGeneration", "dkim2CurrentGeneration", "dkim2TerminalState", "dkim2TerminalReason", "dkim2TerminalTime"}, nil)
	result, err := c.search(ctx, request)
	if goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
		return datasourceadmin.TerminalRecord{}, false, nil
	}
	if err != nil || result == nil || len(result.Entries) != 1 {
		return datasourceadmin.TerminalRecord{}, false, errors.New("terminal unavailable")
	}
	e := result.Entries[0]
	parse := func(name string) (string, error) {
		values := e.GetAttributeValues(name)
		if len(values) != 1 {
			return "", errors.New("terminal unavailable")
		}
		return values[0], nil
	}
	candidateSchema, err := parse(attrSchemaVersion)
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	sourceSchema, err := parse("dkim2SourceSchema")
	if err != nil { return datasourceadmin.TerminalRecord{}, false, err }
	sourceText, err := parse("dkim2SourceGeneration")
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	candidateText, err := parse(attrGeneration)
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	currentText, err := parse("dkim2CurrentGeneration")
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	state, err := parse("dkim2TerminalState")
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	reason, err := parse("dkim2TerminalReason")
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	timestamp, err := parse("dkim2TerminalTime")
	if err != nil {
		return datasourceadmin.TerminalRecord{}, false, err
	}
	source, sourceErr := strconv.ParseUint(sourceText, 10, 64)
	candidate, candidateErr := strconv.ParseUint(candidateText, 10, 64)
	current, currentErr := strconv.ParseUint(currentText, 10, 64)
	digest, digestErr := datasourceadmin.ParseCandidateContentDigest([]byte(e.GetRawAttributeValue(attrCandidateDigest)))
	when, timeErr := time.Parse("20060102150405.000000Z", timestamp)
	if sourceErr != nil || candidateErr != nil || currentErr != nil || digestErr != nil || timeErr != nil {
		return datasourceadmin.TerminalRecord{}, false, errors.New("terminal unavailable")
	}
	record, recordErr := datasourceadmin.NewTerminalRecord(operation, candidateSchema, sourceSchema, source, candidate, current, digest, datasourceadmin.TerminalState(state), reason, when.UTC())
	if recordErr != nil {
		return datasourceadmin.TerminalRecord{}, false, recordErr
	}
	return record, true, nil
}

func terminalEqual(left, right datasourceadmin.TerminalRecord) bool {
	return left.Valid() && right.Valid() && left.Operation().Equal(right.Operation()) && left.CandidateSchema() == right.CandidateSchema() && left.SourceSchema() == right.SourceSchema() && left.SourceGeneration() == right.SourceGeneration() && left.CandidateGeneration() == right.CandidateGeneration() && left.CurrentGeneration() == right.CurrentGeneration() && left.State() == right.State() && left.Reason() == right.Reason() && left.RecordedAt().Equal(right.RecordedAt()) && left.CandidateDigest().Equal(right.CandidateDigest())
}
