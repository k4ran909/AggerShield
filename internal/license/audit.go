package license

import "time"

// auditCap bounds the persisted audit trail so the data file stays small.
const auditCap = 500

// AuditEntry records one admin action on the control plane.
type AuditEntry struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"`           // e.g. "key.generate", "key.revoke", "policy.set"
	Target   string    `json:"target,omitempty"` // key id / name affected
	SourceIP string    `json:"source_ip,omitempty"`
}

// Audit appends an admin action to the (capped, persisted) audit trail.
func (s *Store) Audit(action, target, sourceIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Audit = append(s.d.Audit, AuditEntry{
		Time: time.Now().UTC(), Action: action, Target: target, SourceIP: sourceIP,
	})
	if len(s.d.Audit) > auditCap {
		s.d.Audit = s.d.Audit[len(s.d.Audit)-auditCap:]
	}
	_ = s.save()
}

// AuditLog returns the audit trail, newest first.
func (s *Store) AuditLog() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEntry, len(s.d.Audit))
	for i, e := range s.d.Audit {
		out[len(out)-1-i] = e // reverse → newest first
	}
	return out
}
