package datasourceadmin

import (
	"context"
	"fmt"
	"sync"
)

// PlanSource owns one complete key-free current-snapshot projection.
type PlanSource struct {
	mu         sync.Mutex
	schema     string
	generation uint64
	rows       Rows
	closed     bool
}

// PlanSource creates a detached projection and immediately omits all private PKCS8 fields.
func (s *Snapshot) PlanSource(ctx context.Context) (*PlanSource, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, newError(CodeInvalid)
	}
	schema, generation := s.SchemaVersion(), s.Generation()
	var retained Rows
	if err := s.WithRows(ctx, func(rows Rows) error {
		retained = cloneRows(rows)
		for index := range retained.KeyMaterial {
			clear(retained.KeyMaterial[index].PrivatePKCS8)
			retained.KeyMaterial[index].PrivatePKCS8 = nil
		}
		return nil
	}); err != nil {
		clearRows(&retained)
		return nil, err
	}
	return &PlanSource{schema: schema, generation: generation, rows: retained}, nil
}

// SchemaVersion returns the exact source datasource schema.
func (s *PlanSource) SchemaVersion() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.schema
}

// Generation returns the exact source generation.
func (s *PlanSource) Generation() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0
	}
	return s.generation
}

// WithRows supplies one detached key-free row projection to a bounded callback.
func (s *PlanSource) WithRows(ctx context.Context, use func(Rows) error) error {
	if s == nil || ctx == nil || use == nil || ctx.Err() != nil {
		return newError(CodeInvalid)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return newError(CodeInvalid)
	}
	rows := cloneRows(s.rows)
	s.mu.Unlock()
	defer clearRows(&rows)
	if err := use(rows); err != nil {
		return newError(CodeUnavailable)
	}
	return nil
}

// Clone creates one separately owned key-free projection.
func (s *PlanSource) Clone() (*PlanSource, error) {
	if s == nil {
		return nil, newError(CodeInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, newError(CodeInvalid)
	}
	return &PlanSource{schema: s.schema, generation: s.generation, rows: cloneRows(s.rows)}, nil
}

// Close releases every retained public identity and key projection.
func (s *PlanSource) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	clearRows(&s.rows)
	s.schema = ""
	s.generation = 0
	s.closed = true
	return nil
}

// String returns a constant protected plan-source representation.
func (*PlanSource) String() string { return redacted }

// GoString returns a constant protected plan-source representation.
func (*PlanSource) GoString() string { return redacted }

// Format prevents source identities and public keys from reaching formatting sinks.
func (*PlanSource) Format(state fmt.State, _ rune) { formatProtected(state) }

// MarshalJSON rejects generic protected plan-source serialization.
func (*PlanSource) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }
