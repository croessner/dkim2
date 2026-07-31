package migration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	"github.com/croessner/dkim2/provider"
	goldap "github.com/go-ldap/ldap/v3"
)

type ldapInventoryClient struct {
	mu         sync.Mutex
	connection *goldap.Conn
	baseDN     string
	pageSize   int
	closed     bool
}

// NewLDAPKeyImportClient opens one separate verified-TLS protected-key principal.
func NewLDAPKeyImportClient(
	ctx context.Context,
	source SourceConfig,
	password []byte,
	rootsDER [][]byte,
) (KeyImportClient, func() error, error) {
	client, closeClient, err := NewLDAPInventoryClient(ctx, source, password, rootsDER)
	if err != nil {
		return nil, nil, errors.New("legacy key import unavailable")
	}
	concrete, ok := client.(*ldapInventoryClient)
	if !ok || concrete == nil {
		_ = closeClient()
		return nil, nil, errors.New("legacy key import unavailable")
	}
	return concrete, closeClient, nil
}

// NewLDAPInventoryClient opens one verified-TLS read-only legacy connection.
func NewLDAPInventoryClient(
	ctx context.Context,
	source SourceConfig,
	password []byte,
	rootsDER [][]byte,
) (InventoryClient, func() error, error) {
	if ctx == nil || len(password) == 0 || len(password) > 16<<10 {
		return nil, nil, errors.New("legacy inventory unavailable")
	}
	roots, err := migrationRootPool(rootsDER)
	if err != nil {
		return nil, nil, errors.New("legacy inventory unavailable")
	}
	deadline, found := ctx.Deadline()
	if !found {
		return nil, nil, errors.New("legacy inventory unavailable")
	}
	dialer := net.Dialer{Deadline: deadline}
	raw, err := dialer.DialContext(ctx, "tcp", source.Address)
	if err != nil {
		return nil, nil, errors.New("legacy inventory unavailable")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: source.ServerName, RootCAs: roots,
	}
	var connection *goldap.Conn
	if source.Transport == "starttls" {
		connection = goldap.NewConn(raw, false)
		connection.Start()
		if err := connection.StartTLS(tlsConfig); err != nil {
			_ = connection.Close()
			return nil, nil, errors.New("legacy inventory unavailable")
		}
	} else {
		secured := tls.Client(raw, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, nil, errors.New("legacy inventory unavailable")
		}
		connection = goldap.NewConn(secured, true)
		connection.Start()
	}
	client := &ldapInventoryClient{
		connection: connection, baseDN: source.BaseDN, pageSize: int(source.PageSize),
	}
	if err := client.call(ctx, func() error {
		return connection.Bind(source.BindDN, string(password))
	}); err != nil {
		_ = connection.Close()
		return nil, nil, errors.New("legacy inventory unavailable")
	}
	return client, client.Close, nil
}

// migrationRootPool validates and owns principal-scoped trust roots.
func migrationRootPool(rootsDER [][]byte) (*x509.CertPool, error) {
	if len(rootsDER) == 0 {
		return nil, errors.New("migration trust unavailable")
	}
	roots := x509.NewCertPool()
	for _, encoded := range rootsDER {
		certificate, err := x509.ParseCertificate(bytes.Clone(encoded))
		if err != nil {
			return nil, errors.New("migration trust unavailable")
		}
		roots.AddCert(certificate)
	}
	return roots, nil
}

// Search reads all bounded legacy records with critical RFC 2696 paging.
func (c *ldapInventoryClient) Search(
	ctx context.Context,
	attributes []string,
	maximum int,
	maximumBytes int,
) ([]RawEntry, error) {
	if c == nil || ctx == nil || maximum <= 0 || maximumBytes <= 0 ||
		slices.Contains(attributes, legacyKey) ||
		!slices.Equal(attributes, inventoryAttributes) {
		return nil, errors.New("legacy inventory unavailable")
	}
	output := make([]RawEntry, 0, min(c.pageSize, maximum))
	cookie := []byte(nil)
	bytesRead := 0
	for responses := 0; responses <= maximum; responses++ {
		request := goldap.NewSearchRequest(
			c.baseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			maximum+1, 0, false, "(objectClass=DKIM)", attributes,
			[]goldap.Control{
				datasourceldap.NewCriticalPagingControl(uint32(c.pageSize), cookie),
			},
		)
		request.EnforceSizeLimit = true
		var result *goldap.SearchResult
		if err := c.call(ctx, func() error {
			var searchErr error
			result, searchErr = c.connection.Search(request)
			return searchErr
		}); err != nil || result == nil || len(result.Referrals) != 0 {
			return nil, errors.New("legacy inventory unavailable")
		}
		control, ok := goldap.FindControl(
			result.Controls, goldap.ControlTypePaging,
		).(*goldap.ControlPaging)
		if !ok || control == nil || len(control.Cookie) > 4096 {
			return nil, errors.New("legacy inventory unavailable")
		}
		for _, entry := range result.Entries {
			if entry == nil || len(output) >= maximum ||
				len(entry.DN) > 4096 || len(entry.Attributes) > len(attributes) {
				return nil, errors.New("legacy inventory unavailable")
			}
			raw := RawEntry{
				Attributes: make(map[string][][]byte, len(entry.Attributes)),
			}
			bytesRead += len(entry.DN)
			for _, attribute := range entry.Attributes {
				if attribute == nil || !slices.Contains(attributes, attribute.Name) ||
					len(attribute.ByteValues) == 0 || len(attribute.ByteValues) > 4 {
					return nil, errors.New("legacy inventory unavailable")
				}
				values := make([][]byte, len(attribute.ByteValues))
				for index, value := range attribute.ByteValues {
					if len(value) > 4096 || bytesRead > maximumBytes-len(value) {
						return nil, errors.New("legacy inventory unavailable")
					}
					bytesRead += len(value)
					values[index] = append([]byte(nil), value...)
				}
				raw.Attributes[attribute.Name] = values
			}
			output = append(output, raw)
		}
		if len(control.Cookie) == 0 {
			return output, nil
		}
		cookie = append(cookie[:0], control.Cookie...)
	}
	return nil, errors.New("legacy inventory unavailable")
}

// FetchKey reads one exact active legacy key through the import-only projection.
func (c *ldapInventoryClient) FetchKey(
	ctx context.Context,
	domain string,
	sourceSelector string,
	attributes []string,
	maximum int,
) ([]byte, error) {
	canonicalSelector := strings.ToLower(sourceSelector)
	if c == nil || ctx == nil || maximum != 64<<10 ||
		!slices.Equal(attributes, keyImportAttributes) ||
		provider.ValidateDomainSelector(
			domain, canonicalSelector, provider.AlgorithmRSASHA256,
		) != nil {
		return nil, errors.New("legacy key import unavailable")
	}
	filter := "(&(objectClass=DKIM)(DKIMActive=TRUE)(DKIMDomain=" +
		goldap.EscapeFilter(domain) + ")(DKIMSelector=" +
		goldap.EscapeFilter(sourceSelector) + "))"
	request := goldap.NewSearchRequest(
		c.baseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, 0, false, filter, attributes, nil,
	)
	request.EnforceSizeLimit = true
	var result *goldap.SearchResult
	if err := c.call(ctx, func() error {
		var searchErr error
		result, searchErr = c.connection.Search(request)
		return searchErr
	}); err != nil || result == nil || len(result.Referrals) != 0 ||
		len(result.Entries) != 1 ||
		result.Entries[0] == nil {
		return nil, errors.New("legacy key import unavailable")
	}
	entry := result.Entries[0]
	if len(entry.DN) > 4096 || len(entry.Attributes) != len(attributes) {
		return nil, errors.New("legacy key import unavailable")
	}
	values := make(map[string][][]byte, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		if attribute == nil || !slices.Contains(attributes, attribute.Name) ||
			len(attribute.ByteValues) != 1 {
			return nil, errors.New("legacy key import unavailable")
		}
		value := attribute.ByteValues[0]
		if len(value) == 0 || len(value) > maximum {
			return nil, errors.New("legacy key import unavailable")
		}
		values[attribute.Name] = attribute.ByteValues
	}
	if len(values) != len(attributes) ||
		len(values[legacyDomain]) != 1 ||
		len(values[legacyAssociatedDomain]) != 1 ||
		len(values[legacySelector]) != 1 ||
		len(values[legacyKeyType]) != 1 ||
		len(values[legacyKey]) != 1 ||
		string(values[legacyDomain][0]) != domain ||
		string(values[legacyAssociatedDomain][0]) != domain ||
		string(values[legacySelector][0]) != sourceSelector ||
		(string(values[legacyKeyType][0]) != string(AlgorithmRSA) &&
			string(values[legacyKeyType][0]) != string(AlgorithmEd25519)) {
		return nil, errors.New("legacy key import unavailable")
	}
	return append([]byte(nil), values[legacyKey][0]...), nil
}

// call bounds one LDAP operation and closes the connection on cancellation.
func (c *ldapInventoryClient) call(
	ctx context.Context,
	operation func() error,
) error {
	if c == nil || ctx == nil || operation == nil {
		return errors.New("legacy inventory unavailable")
	}
	deadline, found := ctx.Deadline()
	if !found {
		return errors.New("legacy inventory unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.connection == nil {
		return errors.New("legacy inventory unavailable")
	}
	c.connection.SetTimeout(time.Until(deadline))
	done := make(chan error, 1)
	go func() { done <- operation() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		c.closed = true
		_ = c.connection.Close()
		return ctx.Err()
	}
}

// Close releases the read-only inventory connection.
func (c *ldapInventoryClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.connection == nil {
		return nil
	}
	c.closed = true
	err := c.connection.Close()
	c.connection = nil
	return err
}
