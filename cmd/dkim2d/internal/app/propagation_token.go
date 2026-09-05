package app

import (
	"container/heap"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2"
)

const (
	// propagationTokenBytes is the entropy of one opaque commit token. Its
	// base64url form is 43 characters, inside the contract's 16-512 bound.
	propagationTokenBytes = 32
	// propagationTokenLedgerEntries bounds the reserved-coordinate memory.
	propagationTokenLedgerEntries = 4096
	// propagationTokenRetentionSlack is the margin added to the pending lease
	// so that a token issued just before an expired-lease re-serve still
	// commits the coordinate it was bound to.
	propagationTokenRetentionSlack = time.Minute
)

// propagationTokenRetention derives how long an issued commit token stays
// resolvable from the configured pending lease. The token is only useful
// while the coordinate it reserves is pending, so the retention is the lease
// plus a small margin, never the replay retention: a token that outlives its
// lease by days would accumulate dead entries until the bounded ledger had to
// evict live in-flight tokens, and an evicted live token answers 409, makes
// the adapter defer, and lets the same notification propagate a second time
// once the lease expires.
func propagationTokenRetention(lease time.Duration) time.Duration {
	if lease <= 0 {
		return propagationTokenRetentionSlack
	}
	return lease + propagationTokenRetentionSlack
}

// propagationTokenLedger maps opaque commit tokens to reserved propagation
// coordinates. A commit token is bound to the coordinate, not to one issuing
// attempt: every token issued for a coordinate resolves to that coordinate's
// replay key and commits it through the store's compare-and-set, so a token
// from a superseded attempt still commits. The ledger holds only the opaque
// library key value and never touches the protected storage key. It is
// process-local and bounded; a token the ledger cannot resolve, including
// every token issued before a restart, is unresolved and answered 409, which
// makes the caller defer instead of leaving a coordinate uncommitted.
type propagationTokenLedger struct {
	mu      sync.Mutex
	clock   func() time.Time
	entropy io.Reader
	retain  time.Duration
	byToken map[string]propagationTokenEntry
	expiry  propagationTokenExpiryQueue
}

// propagationTokenExpiryQueue orders retained tokens by expiry so that both
// retention pruning and overflow eviction always remove the entry closest to
// expiring. Eviction is never arbitrary: an arbitrary choice can drop a token
// that an adapter is about to commit while keeping one that is already dead.
type propagationTokenExpiryQueue []propagationTokenExpiry

// propagationTokenExpiry is one queued token and its retention deadline.
type propagationTokenExpiry struct {
	token  string
	expiry time.Time
}

// Len reports the queued token count.
func (q propagationTokenExpiryQueue) Len() int { return len(q) }

// Less orders the queue by earliest expiry.
func (q propagationTokenExpiryQueue) Less(first, second int) bool {
	return q[first].expiry.Before(q[second].expiry)
}

// Swap exchanges two queued tokens.
func (q propagationTokenExpiryQueue) Swap(first, second int) {
	q[first], q[second] = q[second], q[first]
}

// Push appends one queued token.
func (q *propagationTokenExpiryQueue) Push(value any) {
	entry, ok := value.(propagationTokenExpiry)
	if !ok {
		return
	}
	*q = append(*q, entry)
}

// Pop removes and returns the earliest-expiry queued token.
func (q *propagationTokenExpiryQueue) Pop() any {
	old := *q
	last := len(old) - 1
	entry := old[last]
	old[last] = propagationTokenExpiry{}
	*q = old[:last]
	return entry
}

// propagationTokenEntry retains one coordinate key and its expiry. A detached
// entry belongs to a propagation under explicitly disabled replay storage:
// it carries no key and commits without any store transition.
type propagationTokenEntry struct {
	key      dkim2.ReplayKey
	detached bool
	expiry   time.Time
}

// newPropagationTokenLedger constructs one bounded token ledger.
func newPropagationTokenLedger(
	clock func() time.Time,
	retain time.Duration,
	entropy io.Reader,
) (*propagationTokenLedger, error) {
	if clock == nil || retain <= 0 {
		return nil, &DomainError{}
	}
	source := entropy
	if source == nil {
		source = rand.Reader
	}
	return &propagationTokenLedger{
		clock: clock, entropy: source, retain: retain,
		byToken: make(map[string]propagationTokenEntry, 16),
		expiry:  make(propagationTokenExpiryQueue, 0, 16),
	}, nil
}

// Issue mints one fresh token bound to the reserved coordinate's key. A
// coordinate that is reserved again receives another token; both resolve to
// the same coordinate and either commits it.
func (l *propagationTokenLedger) Issue(key dkim2.ReplayKey) (string, error) {
	if l == nil || !key.Valid() {
		return "", &DomainError{}
	}
	now := l.clock().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked(now)
	token, err := l.mintLocked()
	if err != nil {
		return "", err
	}
	l.retainLocked(token, propagationTokenEntry{key: key, expiry: now.Add(l.retain)})
	return token, nil
}

// IssueDetached mints one fresh token that is bound to no coordinate, for a
// propagation whose replay storage is explicitly disabled. The token still
// follows the contract grammar and retention so that the commit operation
// behaves identically for the caller.
func (l *propagationTokenLedger) IssueDetached() (string, error) {
	if l == nil {
		return "", &DomainError{}
	}
	now := l.clock().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked(now)
	token, err := l.mintLocked()
	if err != nil {
		return "", err
	}
	l.retainLocked(token, propagationTokenEntry{detached: true, expiry: now.Add(l.retain)})
	return token, nil
}

// mintLocked draws one fresh base64url token from the ledger's entropy.
func (l *propagationTokenLedger) mintLocked() (string, error) {
	var material [propagationTokenBytes]byte
	if _, err := io.ReadFull(l.entropy, material[:]); err != nil {
		return "", &DomainError{}
	}
	token := base64.RawURLEncoding.EncodeToString(material[:])
	clear(material[:])
	return token, nil
}

// Resolve returns the coordinate key bound to one live token, or reports a
// detached token that commits without a store transition.
func (l *propagationTokenLedger) Resolve(token string) (key dkim2.ReplayKey, detached bool, ok bool) {
	if l == nil || !ValidPropagationCommitToken(token) {
		return dkim2.ReplayKey{}, false, false
	}
	now := l.clock().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked(now)
	entry, present := l.byToken[token]
	if !present {
		return dkim2.ReplayKey{}, false, false
	}
	if entry.detached {
		return dkim2.ReplayKey{}, true, true
	}
	if !entry.key.Valid() {
		return dkim2.ReplayKey{}, false, false
	}
	return entry.key, false, true
}

// expireLocked drops every entry whose retention window has passed, earliest
// expiry first.
func (l *propagationTokenLedger) expireLocked(now time.Time) {
	for len(l.expiry) > 0 && !now.Before(l.expiry[0].expiry) {
		l.dropEarliestLocked()
	}
}

// retainLocked stores one fresh entry, evicting the entry closest to expiring
// when the bounded ledger is full. Because retention is derived from the
// pending lease, a full ledger means more live reservations than the bound
// admits; the entry nearest its own expiry is then the least useful one to
// keep, and it is always chosen deterministically.
func (l *propagationTokenLedger) retainLocked(token string, entry propagationTokenEntry) {
	for len(l.byToken) >= propagationTokenLedgerEntries && len(l.expiry) > 0 {
		l.dropEarliestLocked()
	}
	l.byToken[token] = entry
	heap.Push(&l.expiry, propagationTokenExpiry{token: token, expiry: entry.expiry})
}

// dropEarliestLocked removes the earliest-expiry queued token from both the
// ordering queue and the resolution map.
func (l *propagationTokenLedger) dropEarliestLocked() {
	queued, ok := heap.Pop(&l.expiry).(propagationTokenExpiry)
	if !ok {
		return
	}
	delete(l.byToken, queued.token)
}

// size reports the current bounded ledger occupancy.
func (l *propagationTokenLedger) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.byToken)
}

// ValidPropagationCommitToken accepts only the contract's bounded base64url
// token grammar. A token outside the grammar is never looked up.
func ValidPropagationCommitToken(token string) bool {
	if len(token) < 16 || len(token) > 512 {
		return false
	}
	for index := range len(token) {
		character := token[index]
		letter := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

// String returns a content-free token-ledger representation.
func (*propagationTokenLedger) String() string { return propagationRedacted }

// GoString returns a content-free token-ledger representation.
func (*propagationTokenLedger) GoString() string { return propagationRedacted }

// Format prevents formatting from traversing tokens and coordinates.
func (*propagationTokenLedger) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, propagationRedacted)
}
