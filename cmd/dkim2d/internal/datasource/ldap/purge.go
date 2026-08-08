package ldap

import (
	"context"
	"crypto/subtle"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
	goldap "github.com/go-ldap/ldap/v3"
)

// purgeClient is the deliberately small destructive LDAP transport seam. It
// never exposes private key values to the purger.
type purgeClient interface {
	Client
	ReadCurrentOptional(context.Context) (Entry, bool, error)
	ReadGenerationRootOptional(context.Context, uint64) (Entry, bool, error)
	ReadAdministrationLock(context.Context) (datasourceadmin.AdministrationLockObservation, error)
	ListPurgeEntries(context.Context, uint64, datasourceadmin.GenerationLimits) ([]string, error)
	DeletePurgeEntry(context.Context, string) error
	PurgeGenerationRoot(uint64) string
}

// PurgeExecutor owns LDAP leaf-first destruction under one dedicated purger
// bind. A transport ambiguity is deliberately surfaced for explicit reconcile.
type PurgeExecutor struct {
	connector   AdministrationConnector
	generations datasourceadmin.GenerationLimits
}

// NewPurgeExecutor validates the fourth LDAP authority and finite inventory
// bounds before permitting a destructive provider adapter to be constructed.
func NewPurgeExecutor(connector AdministrationConnector, generations datasourceadmin.GenerationLimits) (*PurgeExecutor, error) {
	if connector == nil || generations.Validate() != nil || !connector.AdministrationAuthority().Valid() {
		return nil, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	return &PurgeExecutor{connector: connector, generations: generations}, nil
}

// Purge executes one exact protected plan once. It never retries a failed LDAP
// delete because an LDAP disconnect can leave an unknown partial tree.
func (e *PurgeExecutor) Purge(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	return e.apply(ctx, command, false)
}

// Reconcile explicitly resumes an interrupted exact plan. It first proves the
// same noncurrent root and then removes only descendants of that root; an
// absent root is the sole idempotent completion proof.
func (e *PurgeExecutor) Reconcile(ctx context.Context, command rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	return e.apply(ctx, command, true)
}

// apply opens one purger session and applies or explicitly reconciles every
// exact target without allowing the caller to choose arbitrary LDAP DNs.
func (e *PurgeExecutor) apply(ctx context.Context, command rotationadmin.PurgeCommand, reconcile bool) (rotationadmin.PurgeExecutionResult, error) {
	if e == nil || e.connector == nil || ctx == nil || ctx.Err() != nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	raw, err := e.connector.Connect(ctx)
	if err != nil || raw == nil {
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	client, ok := raw.(purgeClient)
	if !ok {
		_ = raw.Close()
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeInvalid)
	}
	defer client.Close() //nolint:errcheck // The outcome is already classified by the mutation/readback path.
	err = command.WithTargets(ctx, func(targets []admincontract.PurgeTarget) error {
		for _, target := range targets {
			if targetErr := e.applyTarget(ctx, client, command, target, reconcile); targetErr != nil {
				return targetErr
			}
		}
		return nil
	})
	if err != nil {
		client.Discard()
		return rotationadmin.PurgeExecutionResult{Unknown: true}, datasourceadmin.NewError(datasourceadmin.CodeUnavailable)
	}
	return rotationadmin.PurgeExecutionResult{Committed: true}, nil
}

// applyTarget verifies current and lock state before resolving the exact target
// subtree. The root is deleted only after every descendant has been removed.
func (e *PurgeExecutor) applyTarget(ctx context.Context, client purgeClient, command rotationadmin.PurgeCommand, target admincontract.PurgeTarget, reconcile bool) error {
	if target.Generation == 0 || target.Generation == command.CurrentGeneration() || !target.ContentDigest.Valid() ||
		(target.Lifecycle != "active_history" && target.Lifecycle != "never_active") {
		return errors.New("ldap purge denied")
	}
	lock, err := client.ReadAdministrationLock(ctx)
	if err != nil || !lock.Valid() || lock.Claimed() {
		return errors.New("ldap purge fence unavailable")
	}
	current, present, err := client.ReadCurrentOptional(ctx)
	if err != nil || !present {
		return errors.New("ldap purge fence unavailable")
	}
	defer clearEntry(&current)
	currentMetadata, err := mapCurrentMetadata(current)
	if err != nil || currentMetadata.generation != command.CurrentGeneration() {
		return errors.New("ldap purge fence unavailable")
	}
	root, rootPresent, err := client.ReadGenerationRootOptional(ctx, target.Generation)
	if err != nil || !rootPresent {
		if reconcile && err == nil && !rootPresent {
			return nil
		}
		return errors.New("ldap purge target unavailable")
	}
	defer clearEntry(&root)
	metadata, err := mapGenerationMetadata(root)
	metadataDigest, targetDigest := metadata.digest.Bytes(), target.ContentDigest.Bytes()
	defer clear(metadataDigest)
	defer clear(targetDigest)
	if err != nil || metadata.generation != target.Generation || metadata.schema != target.Schema ||
		metadata.state != datasourceadmin.StateCommitted || subtle.ConstantTimeCompare(metadataDigest, targetDigest) != 1 ||
		(target.Lifecycle == "active_history") != metadata.wasActive {
		return errors.New("ldap purge target denied")
	}
	entries, err := client.ListPurgeEntries(ctx, target.Generation, e.generations)
	if err != nil {
		return errors.New("ldap purge target unavailable")
	}
	if err := orderPurgeEntries(entries, target.Generation, client); err != nil {
		return err
	}
	for _, dn := range entries {
		if err := client.DeletePurgeEntry(ctx, dn); err != nil {
			return errors.New("ldap purge outcome unknown")
		}
	}
	_, present, err = client.ReadGenerationRootOptional(ctx, target.Generation)
	if err != nil || present {
		return errors.New("ldap purge outcome unknown")
	}
	return nil
}

// orderPurgeEntries proves all returned DNs are unique descendants of the one
// exact generated root, then orders leaves before containers and root last.
func orderPurgeEntries(entries []string, generation uint64, client purgeClient) error {
	if len(entries) == 0 || generation == 0 {
		return errors.New("ldap purge target unavailable")
	}
	root, err := goldap.ParseDN(client.PurgeGenerationRoot(generation))
	if err != nil {
		return errors.New("ldap purge target unavailable")
	}
	seen := make(map[string]struct{}, len(entries))
	depth := make(map[string]int, len(entries))
	rootFound := false
	for _, value := range entries {
		dn, parseErr := goldap.ParseDN(value)
		if parseErr != nil || len(dn.RDNs) < len(root.RDNs) || !(&goldap.DN{RDNs: dn.RDNs[len(dn.RDNs)-len(root.RDNs):]}).Equal(root) {
			return errors.New("ldap purge target denied")
		}
		canonical := strings.ToLower(value)
		if _, duplicate := seen[canonical]; duplicate {
			return errors.New("ldap purge target denied")
		}
		seen[canonical] = struct{}{}
		depth[value] = len(dn.RDNs)
		rootFound = rootFound || root.Equal(dn)
	}
	if !rootFound {
		return errors.New("ldap purge target unavailable")
	}
	sort.Slice(entries, func(left, right int) bool {
		if depth[entries[left]] != depth[entries[right]] {
			return depth[entries[left]] > depth[entries[right]]
		}
		return entries[left] < entries[right]
	})
	return nil
}

// ReadGenerationRootOptional reads exact generation metadata or proves its
// root absent for destructive completion reconciliation.
func (c *goLDAPClient) ReadGenerationRootOptional(ctx context.Context, generation uint64) (Entry, bool, error) {
	if c == nil || generation == 0 {
		return Entry{}, false, errors.New("ldap purge target unavailable")
	}
	return c.readOptionalMetadata(ctx, c.generationRoot(generation))
}

// PurgeGenerationRoot returns the exact provider-owned root for one destructive
// target; callers cannot provide an arbitrary base DN.
func (c *goLDAPClient) PurgeGenerationRoot(generation uint64) string {
	return c.generationRoot(generation)
}

// ListPurgeEntries enumerates one exact subtree with critical paging and no
// attribute projection, so a purger never reads key material while reconciling.
func (c *goLDAPClient) ListPurgeEntries(ctx context.Context, generation uint64, limits datasourceadmin.GenerationLimits) ([]string, error) {
	if c == nil || generation == 0 || limits.Validate() != nil {
		return nil, errors.New("ldap purge target unavailable")
	}
	root := c.generationRoot(generation)
	cookie := []byte(nil)
	entries := make([]string, 0, 16)
	maximum := int(limits.MaxSnapshotRows) + len(generationUnits) + 1
	for page := 0; page <= maximum; page++ {
		request := goldap.NewSearchRequest(root, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, maximum, 0, false,
			"(objectClass=*)", []string{"1.1"}, []goldap.Control{newCriticalPagingControl(uint32(min(maximum, 256)), cookie)})
		request.EnforceSizeLimit = true
		result, err := c.search(ctx, request)
		if err != nil || result == nil || len(result.Referrals) != 0 {
			return nil, errors.New("ldap purge target unavailable")
		}
		for _, entry := range result.Entries {
			if entry == nil || entry.DN == "" || len(entries) >= maximum {
				return nil, errors.New("ldap purge target unavailable")
			}
			entries = append(entries, entry.DN)
		}
		paging, ok := goldap.FindControl(result.Controls, goldap.ControlTypePaging).(*goldap.ControlPaging)
		if !ok || paging == nil || len(paging.Cookie) > 4096 {
			return nil, errors.New("ldap purge target unavailable")
		}
		if len(paging.Cookie) == 0 {
			return entries, nil
		}
		cookie = append(cookie[:0], paging.Cookie...)
	}
	return nil, errors.New("ldap purge target unavailable")
}

// DeletePurgeEntry performs one exact LDAP delete. Any error discards the
// session because the server outcome cannot be inferred from the transport.
func (c *goLDAPClient) DeletePurgeEntry(ctx context.Context, dn string) error {
	if c == nil || dn == "" || len(dn) > 4096 {
		return errors.New("ldap purge target unavailable")
	}
	request := goldap.NewDelRequest(dn, nil)
	if err := c.call(ctx, func() error { return c.connection.Del(request) }); err != nil {
		c.Discard()
		return errors.New("ldap purge outcome unknown")
	}
	return nil
}

// purgeGenerationRootDN returns the exact root form for focused destructive
// transport tests without exposing arbitrary DN construction to callers.
func purgeGenerationRootDN(base string, generation uint64) string {
	return "dkim2Generation=" + goldap.EscapeDN(strconv.FormatUint(generation, 10)) + ",ou=generations," + base
}
