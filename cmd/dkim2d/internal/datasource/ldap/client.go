package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

// ConnectionConfig owns one verified single-authority LDAP endpoint.
type ConnectionConfig struct {
	Address     string
	ServerName  string
	BaseDN      string
	BindDN      string
	Password    []byte
	RootCAs     *x509.CertPool
	UseStartTLS bool
}

// Validate rejects anonymous, unverified, multi-authority, or incomplete configuration.
func (c ConnectionConfig) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || portNumber == 0 || host == "" || c.ServerName == "" ||
		c.BaseDN == "" || c.BindDN == "" || len(c.Password) == 0 ||
		c.RootCAs == nil || len(c.Address) > 512 || len(c.ServerName) > 253 ||
		len(c.BaseDN) > 4096 || len(c.BindDN) > 4096 || len(c.Password) > 16<<10 {
		return errors.New("invalid ldap connection configuration")
	}
	return nil
}

// String returns a constant protected connection summary.
func (ConnectionConfig) String() string { return loaderRedacted }

// GoString returns a constant protected connection representation.
func (ConnectionConfig) GoString() string { return loaderRedacted }

// Format prevents formatting verbs from exposing connection facts.
func (ConnectionConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, loaderRedacted)
}

// MarshalJSON emits an empty object without connection facts.
func (ConnectionConfig) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// GoLDAPConnector opens one verified-TLS go-ldap connection without fallback.
type GoLDAPConnector struct {
	config    ConnectionConfig
	authority AdministrationAuthority
}

// NewGoLDAPConnector validates one syntactic LDAP connection and derives an
// administration authority only for the closed canonical service-DN grammar.
func NewGoLDAPConnector(config ConnectionConfig) (*GoLDAPConnector, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	parsed, err := goldap.ParseDN(config.BindDN)
	if err != nil || parsed == nil || len(parsed.RDNs) == 0 {
		return nil, errors.New("invalid ldap connection configuration")
	}
	authority, _ := newAdministrationAuthority(config.BindDN)
	config.Password = append([]byte(nil), config.Password...)
	config.RootCAs = config.RootCAs.Clone()
	return &GoLDAPConnector{config: config, authority: authority}, nil
}

// AdministrationAuthority returns the connector's opaque canonical bind
// identity without exposing the configured DN.
func (c *GoLDAPConnector) AdministrationAuthority() AdministrationAuthority {
	if c == nil {
		return AdministrationAuthority{}
	}
	return c.authority
}

// Close clears retained connector credentials after the one-shot offline workflow.
func (c *GoLDAPConnector) Close() error {
	if c == nil {
		return nil
	}
	clear(c.config.Password)
	c.config = ConnectionConfig{}
	c.authority = AdministrationAuthority{}
	return nil
}

// Connect establishes TLS before simple bind and returns one owned client.
func (c *GoLDAPConnector) Connect(ctx context.Context) (Client, error) {
	if c == nil || ctx == nil || c.config.Validate() != nil {
		return nil, errors.New("ldap connection unavailable")
	}
	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", c.config.Address)
	if err != nil {
		return nil, errors.New("ldap connection unavailable")
	}
	deadline, found := ctx.Deadline()
	if !found {
		_ = raw.Close()
		return nil, errors.New("ldap connection unavailable")
	}
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, errors.New("ldap connection unavailable")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: c.config.ServerName,
		RootCAs: c.config.RootCAs,
	}
	var connection *goldap.Conn
	if c.config.UseStartTLS {
		connection = goldap.NewConn(raw, false)
		connection.Start()
		if err := connection.StartTLS(tlsConfig); err != nil {
			_ = connection.Close()
			return nil, errors.New("ldap connection unavailable")
		}
	} else {
		tlsConnection := tls.Client(raw, tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, errors.New("ldap connection unavailable")
		}
		connection = goldap.NewConn(tlsConnection, true)
		connection.Start()
	}
	client := &goLDAPClient{connection: connection, baseDN: c.config.BaseDN}
	if err := client.call(ctx, func() error {
		return connection.Bind(c.config.BindDN, string(c.config.Password))
	}); err != nil {
		_ = connection.Close()
		return nil, errors.New("ldap connection unavailable")
	}
	return client, nil
}

type goLDAPClient struct {
	mu         sync.Mutex
	connection *goldap.Conn
	baseDN     string
	discarded  bool
}

// ReadCurrent reads exactly one current publication metadata entry.
func (c *goLDAPClient) ReadCurrent(ctx context.Context) (Entry, error) {
	return c.readMetadata(ctx, "cn=current,"+c.baseDN)
}

// ReadGenerationRoot reads one exact immutable generation root.
func (c *goLDAPClient) ReadGenerationRoot(ctx context.Context, generation uint64) (Entry, error) {
	if generation == 0 {
		return Entry{}, errors.New("ldap generation unavailable")
	}
	base := "dkim2Generation=" + goldap.EscapeDN(strconv.FormatUint(generation, 10)) +
		",ou=generations," + c.baseDN
	return c.readMetadata(ctx, base)
}

// readMetadata maps exactly one base-object metadata search.
func (c *goLDAPClient) readMetadata(ctx context.Context, base string) (Entry, error) {
	request := goldap.NewSearchRequest(
		base, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 2, 0, false,
		"(objectClass=dkim2Dataset)",
		metadataProjection(),
		nil,
	)
	request.EnforceSizeLimit = true
	result, err := c.search(ctx, request)
	if err != nil || result == nil ||
		len(result.Referrals) != 0 || len(result.Entries) != 1 {
		return Entry{}, errors.New("ldap metadata unavailable")
	}
	defer clearLDAPProtectedAttributeBytes(result.Entries)
	entry, err := convertEntry(RecordClassDataset, result.Entries[0])
	if err != nil {
		return Entry{}, errors.New("ldap metadata unavailable")
	}
	return entry, nil
}

// metadataProjection returns every immutable fence needed to verify current
// and source-bound campaign generation metadata.
func metadataProjection() []string {
	return []string{
		attrSchemaVersion, attrGeneration, attrDatasetState,
		attrCandidateDigest, attrOperationID, attrSourceGeneration, attrWasActive,
	}
}

// SearchPage performs one critical simple-paged exact-generation search.
func (c *goLDAPClient) SearchPage(
	ctx context.Context,
	class RecordClass,
	generation uint64,
	cookie []byte,
	pageSize int,
	sizeLimit int,
) (Page, error) {
	base, objectClass, attributes, err := c.searchShape(class, generation)
	if err != nil || pageSize <= 0 || pageSize > 256 || sizeLimit <= 0 {
		return Page{}, errors.New("ldap search unavailable")
	}
	paging := newCriticalPagingControl(uint32(pageSize), cookie)
	filter := "(&(objectClass=" + goldap.EscapeFilter(objectClass) +
		")(dkim2Generation=" + goldap.EscapeFilter(strconv.FormatUint(generation, 10)) + "))"
	request := goldap.NewSearchRequest(
		base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		sizeLimit, 0, false, filter, attributes, []goldap.Control{paging},
	)
	request.EnforceSizeLimit = true
	result, err := c.search(ctx, request)
	if err != nil || result == nil || len(result.Referrals) != 0 {
		c.Discard()
		return Page{}, errors.New("ldap search unavailable")
	}
	if class == RecordClassKeyMaterial {
		defer clearLDAPPrivateAttributeBytes(result.Entries)
	}
	responseControl := goldap.FindControl(result.Controls, goldap.ControlTypePaging)
	responsePaging, ok := responseControl.(*goldap.ControlPaging)
	if !ok || responsePaging == nil {
		return Page{}, errors.New("ldap paging unavailable")
	}
	if len(responsePaging.Cookie) > 4096 {
		c.Discard()
		return Page{}, errors.New("ldap paging unavailable")
	}
	page := Page{Cookie: append([]byte(nil), responsePaging.Cookie...)}
	success := false
	defer func() {
		if class == RecordClassKeyMaterial && !success {
			clearEntries(page.Entries)
		}
	}()
	for _, source := range result.Entries {
		entry, convertErr := convertEntry(class, source)
		if convertErr != nil {
			return Page{}, errors.New("ldap search unavailable")
		}
		page.Bytes += len(source.DN) + entryBytes(entry)
		if page.Bytes > 4<<20 {
			return Page{}, errors.New("ldap search unavailable")
		}
		page.Entries = append(page.Entries, entry)
	}
	success = true
	return page, nil
}

// clearLDAPPrivateAttributeBytes destroys private values retained by go-ldap
// entries after the strict detached projection has been created.
func clearLDAPPrivateAttributeBytes(entries []*goldap.Entry) {
	clearLDAPAttributes(entries, attrPrivatePKCS8)
}

// clearLDAPProtectedAttributeBytes destroys all administration-sensitive source values.
func clearLDAPProtectedAttributeBytes(entries []*goldap.Entry) {
	clearLDAPAttributes(entries, attrPrivatePKCS8, attrCandidateDigest, attrOperationID, attrAdminLockOwner)
}

// clearLDAPAttributes destroys selected values still owned by go-ldap entries.
func clearLDAPAttributes(entries []*goldap.Entry, names ...string) {
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		for _, attribute := range entry.Attributes {
			if attribute == nil || !containsFold(names, attribute.Name) {
				continue
			}
			for index := range attribute.ByteValues {
				clear(attribute.ByteValues[index])
				attribute.ByteValues[index] = nil
			}
			attribute.ByteValues = nil
			for index := range attribute.Values {
				attribute.Values[index] = ""
			}
			attribute.Values = nil
		}
	}
}

// Abandon sends one page-size-zero request with the last accepted cookie.
func (c *goLDAPClient) Abandon(
	ctx context.Context,
	class RecordClass,
	generation uint64,
	cookie []byte,
) error {
	base, objectClass, attributes, err := c.searchShape(class, generation)
	if err != nil || len(cookie) == 0 {
		return errors.New("ldap abandonment unavailable")
	}
	paging := newCriticalPagingControl(0, cookie)
	filter := "(&(objectClass=" + goldap.EscapeFilter(objectClass) +
		")(dkim2Generation=" + goldap.EscapeFilter(strconv.FormatUint(generation, 10)) + "))"
	request := goldap.NewSearchRequest(
		base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		1, 0, false, filter, attributes, []goldap.Control{paging},
	)
	_, err = c.search(ctx, request)
	return err
}

type criticalPagingControl struct {
	size   uint32
	cookie []byte
}

// newCriticalPagingControl constructs the mandatory RFC 2696 request control.
func newCriticalPagingControl(size uint32, cookie []byte) *criticalPagingControl {
	return &criticalPagingControl{size: size, cookie: append([]byte(nil), cookie...)}
}

// NewCriticalPagingControl constructs a mandatory RFC 2696 control for sibling
// daemon-owned read-only LDAP workflows.
func NewCriticalPagingControl(size uint32, cookie []byte) goldap.Control {
	return newCriticalPagingControl(size, cookie)
}

// GetControlType returns the RFC 2696 control OID.
func (*criticalPagingControl) GetControlType() string { return goldap.ControlTypePaging }

// Encode emits a critical RFC 2696 control with an opaque cookie.
func (c *criticalPagingControl) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		goldap.ControlTypePaging, "Control Type",
	))
	packet.AppendChild(ber.NewBoolean(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality",
	))
	value := ber.Encode(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value",
	)
	sequence := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Paging",
	)
	sequence.AppendChild(ber.NewInteger(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.size), "Size",
	))
	cookie := ber.Encode(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie",
	)
	cookie.Value = append([]byte(nil), c.cookie...)
	_, _ = cookie.Data.Write(c.cookie)
	sequence.AppendChild(cookie)
	value.AppendChild(sequence)
	packet.AppendChild(value)
	return packet
}

// String returns a content-free control summary.
func (*criticalPagingControl) String() string { return "critical_paging_control" }

// searchShape returns fixed base, class, and projection for one record class.
func (c *goLDAPClient) searchShape(
	class RecordClass,
	generation uint64,
) (string, string, []string, error) {
	if generation == 0 {
		return "", "", nil, errors.New("ldap search unavailable")
	}
	root := "dkim2Generation=" + goldap.EscapeDN(strconv.FormatUint(generation, 10)) +
		",ou=generations," + c.baseDN
	switch class {
	case RecordClassHandle:
		return "ou=" + handlesUnit + "," + root, handleObjectClass,
			[]string{attrGeneration, attrHandleID}, nil
	case RecordClassProfile:
		return "ou=" + profilesUnit + "," + root, profileObjectClass,
			[]string{attrGeneration, attrProfileID, attrSigningDomain,
				attrRecordStatus, attrNotBefore, attrNotAfter}, nil
	case RecordClassCredential:
		return "ou=" + credentialsUnit + "," + root, credentialObjectClass,
			[]string{attrGeneration, attrProfileID, attrAlgorithm,
				attrSelector, attrPublicSPKI, attrHandleID}, nil
	case RecordClassPolicy:
		return "ou=" + policiesUnit + "," + root, policyObjectClass,
			[]string{attrGeneration, attrTenantID, attrSigningDomain,
				attrProfileUse, attrProfileID, attrRecordStatus,
				attrRollout, attrCompatibility, attrFeedbackRouteID}, nil
	case RecordClassKeyMaterial:
		return "ou=" + keyMaterialUnit + "," + root, keyMaterialObjectClass,
			[]string{attrGeneration, attrTenantID, attrSigningDomain,
				attrProfileUse, attrHandleID, attrAlgorithm, attrPublicSPKI,
				attrPrivatePKCS8}, nil
	default:
		return "", "", nil, errors.New("ldap search unavailable")
	}
}

// search runs one request with deadline and cancellation-owned connection close.
func (c *goLDAPClient) search(
	ctx context.Context,
	request *goldap.SearchRequest,
) (*goldap.SearchResult, error) {
	var result *goldap.SearchResult
	err := c.call(ctx, func() error {
		var searchErr error
		result, searchErr = c.connection.Search(request)
		return searchErr
	})
	return result, err
}

// call applies the original deadline and closes the connection on cancellation.
func (c *goLDAPClient) call(ctx context.Context, operation func() error) error {
	if c == nil || ctx == nil || operation == nil {
		return errors.New("ldap operation unavailable")
	}
	deadline, found := ctx.Deadline()
	if !found {
		return errors.New("ldap operation unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connection == nil || c.discarded {
		return errors.New("ldap operation unavailable")
	}
	c.connection.SetTimeout(time.Until(deadline))
	done := make(chan error, 1)
	go func() { done <- operation() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		c.discarded = true
		_ = c.connection.Close()
		return ctx.Err()
	}
}

// Discard closes a connection that may not safely return to reuse.
func (c *goLDAPClient) Discard() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.discarded = true
	if c.connection != nil {
		_ = c.connection.Close()
	}
}

// Close releases the owned LDAP connection.
func (c *goLDAPClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connection == nil {
		return nil
	}
	err := c.connection.Close()
	c.connection = nil
	return err
}

// convertEntry copies only requested LDAP attributes into the strict mapper shape.
func convertEntry(class RecordClass, source *goldap.Entry) (entry Entry, resultErr error) {
	if source == nil || len(source.DN) > 4096 || len(source.Attributes) > 24 {
		return Entry{}, errors.New("ldap entry unavailable")
	}
	entry = Entry{Class: class, Attributes: make(map[string][][]byte, len(source.Attributes))}
	success := false
	defer func() {
		if !success {
			clearEntries([]Entry{entry})
			clearLDAPProtectedAttributeBytes([]*goldap.Entry{source})
			entry = Entry{}
		}
	}()
	for _, attribute := range source.Attributes {
		if attribute == nil || len(attribute.Name) == 0 || len(attribute.Name) > 128 ||
			len(attribute.ByteValues) == 0 || len(attribute.ByteValues) > 4 {
			return Entry{}, errors.New("ldap entry unavailable")
		}
		values := make([][]byte, len(attribute.ByteValues))
		for index := range attribute.ByteValues {
			maximum := 4096
			if attribute.Name == attrPrivatePKCS8 {
				maximum = maxPrivateAttributeBytes
			}
			if len(attribute.ByteValues[index]) > maximum {
				for valueIndex := range values {
					clear(values[valueIndex])
				}
				return Entry{}, errors.New("ldap entry unavailable")
			}
			values[index] = append([]byte(nil), attribute.ByteValues[index]...)
		}
		if _, duplicate := entry.Attributes[attribute.Name]; duplicate {
			for index := range values {
				clear(values[index])
			}
			return Entry{}, errors.New("ldap entry unavailable")
		}
		entry.Attributes[attribute.Name] = values
	}
	success = true
	return entry, nil
}
