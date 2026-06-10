package license

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// Key is an issued license. The plaintext key is shown only once at creation;
// only its SHA-256 hash is stored, so a leak of the data file does not expose
// usable keys.
type Key struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"` // customer / service name
	Hash      string     `json:"hash"`
	Note      string     `json:"note,omitempty"`
	Created   time.Time  `json:"created"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// AgentStatus is the latest telemetry reported by the agent using a key.
type AgentStatus struct {
	KeyID      string           `json:"key_id"`
	Hostname   string           `json:"hostname"`
	Version    string           `json:"version"`
	Protecting string           `json:"protecting"`
	SourceIP   string           `json:"source_ip"`   // observed by the server (trusted)
	ReportedIP string           `json:"reported_ip"` // self-reported by the agent
	FirstSeen  time.Time        `json:"first_seen"`
	LastSeen   time.Time        `json:"last_seen"`
	Stats      map[string]int64 `json:"stats,omitempty"`
}

type data struct {
	Keys     map[string]*Key          `json:"keys"`     // by key ID
	Agents   map[string]*AgentStatus  `json:"agents"`   // by key ID
	Policies map[string]*PolicyRecord `json:"policies"` // by key ID
}

// Store is a concurrency-safe, file-backed license store.
type Store struct {
	mu     sync.RWMutex
	path   string
	d      *data
	byHash map[string]string // hash -> key ID, for O(1) validation
}

// Open loads the store from path, creating an empty one if absent.
func Open(path string) (*Store, error) {
	s := &Store{
		path:   path,
		d:      &data{Keys: map[string]*Key{}, Agents: map[string]*AgentStatus{}, Policies: map[string]*PolicyRecord{}},
		byHash: map[string]string{},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, s.save()
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s.d); err != nil {
		return nil, fmt.Errorf("license store: %w", err)
	}
	if s.d.Keys == nil {
		s.d.Keys = map[string]*Key{}
	}
	if s.d.Agents == nil {
		s.d.Agents = map[string]*AgentStatus{}
	}
	if s.d.Policies == nil {
		s.d.Policies = map[string]*PolicyRecord{}
	}
	for _, k := range s.d.Keys {
		s.byHash[k.Hash] = k.ID
	}
	return s, nil
}

// Generate issues a new key, returning the one-time plaintext and its record.
func (s *Store) Generate(name, note string) (plaintext string, key *Key, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plaintext = KeyPrefix + randHex(24)
	id := "k_" + randHex(5)
	k := &Key{
		ID:      id,
		Name:    name,
		Hash:    hashKey(plaintext),
		Note:    note,
		Created: time.Now().UTC(),
	}
	s.d.Keys[id] = k
	s.byHash[k.Hash] = id
	return plaintext, k, s.save()
}

// Validate looks up a plaintext key. ok is false for unknown or revoked keys.
func (s *Store) Validate(plaintext string) (*Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, found := s.byHash[hashKey(plaintext)]
	if !found {
		return nil, false
	}
	k := s.d.Keys[id]
	if k == nil || k.Revoked {
		return k, false
	}
	return k, true
}

// Revoke marks a key revoked. Reports whether it existed.
func (s *Store) Revoke(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.d.Keys[id]
	if k == nil {
		return false, nil
	}
	if !k.Revoked {
		now := time.Now().UTC()
		k.Revoked = true
		k.RevokedAt = &now
	}
	return true, s.save()
}

// RecordHeartbeat upserts the latest agent status for a key.
func (s *Store) RecordHeartbeat(keyID string, st AgentStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	st.KeyID = keyID
	st.LastSeen = now
	if prev := s.d.Agents[keyID]; prev != nil {
		st.FirstSeen = prev.FirstSeen
	} else {
		st.FirstSeen = now
	}
	s.d.Agents[keyID] = &st
	return s.save()
}

// Keys returns all keys, newest first.
func (s *Store) Keys() []*Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Key, 0, len(s.d.Keys))
	for _, k := range s.d.Keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Agent returns the latest status for a key ID (or nil).
func (s *Store) Agent(keyID string) *AgentStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.d.Agents[keyID]
}

// save atomically persists the store (temp file + rename).
func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
