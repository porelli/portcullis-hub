package hub

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	"filippo.io/age"

	"github.com/portcullis/hub/internal/aigate"
)

// The AI credential store (contract §15.4 mcp-credentials.json; G70: not
// file sharing's credstore.go): per (instance, companion, user) the app
// credential a mint hook returned, and one caller secret per
// identity_headers companion, each as ASCII-armored age ciphertext to the
// gate's recipient. The Hub never holds an identity: it can add, replace,
// mark revoking or drop an entry, never read one back. The file is the
// store (0640, group 10001, atomic, validated with the gate's rules
// before every write); its own mutex, never Hub.mu. Mint and revoke
// (Task 13) call it; audit actions there are ai.credential.*.

// aiCredStore is <data>/mcp-credentials.json.
type aiCredStore struct {
	mu        sync.Mutex
	path      string
	recipient func() (*age.X25519Recipient, error)
	file      *aigate.CredFile // nil: not loaded yet
}

// creds is the Hub's AI credential store (created on first use).
func (h *Hub) creds() *aiCredStore {
	h.credsOnce.Do(func() {
		h.aiCreds = &aiCredStore{path: h.credsPath(), recipient: func() (*age.X25519Recipient, error) {
			r := h.gateRecipient()
			if r == nil {
				return nil, errors.New("no mcp-gate recipient (HUB_MCP_GATE_RECIPIENT_FILE): AI credentials can't be stored")
			}
			return r, nil
		}}
	})
	return h.aiCreds
}

// loadLocked reads the file once (missing = empty). A file that doesn't
// decode with the gate's rules is an error, never replaced: it may hold
// revoking entries whose app-side revocation is still owed.
func (s *aiCredStore) loadLocked() error {
	if s.file != nil {
		return nil
	}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.file = &aigate.CredFile{Version: 1, Credentials: []aigate.Credential{}, CallerSecrets: []aigate.CallerSecret{}}
		return nil
	case err != nil:
		return fmt.Errorf("%s: %v", aigate.CredsFileName, err)
	}
	f, err := aigate.DecodeCredFile(b)
	if err != nil {
		return fmt.Errorf("%s doesn't decode (%v): fix or remove it", aigate.CredsFileName, err)
	}
	s.file = f
	return nil
}

// commitLocked writes next (validated first); on success it becomes the
// store's state, on failure nothing changes.
func (s *aiCredStore) commitLocked(next *aigate.CredFile) error {
	slices.SortFunc(next.Credentials, func(a, b aigate.Credential) int {
		return slices.Compare([]string{a.Instance, a.Companion, a.User}, []string{b.Instance, b.Companion, b.User})
	})
	slices.SortFunc(next.CallerSecrets, func(a, b aigate.CallerSecret) int { return strings.Compare(a.Ref, b.Ref) })
	if err := aigate.WriteCredFile(s.path, next); err != nil {
		return err
	}
	s.file = next
	return nil
}

func (s *aiCredStore) cloneLocked() *aigate.CredFile {
	return &aigate.CredFile{Version: 1, Credentials: slices.Clone(s.file.Credentials), CallerSecrets: slices.Clone(s.file.CallerSecrets)}
}

func credIndex(f *aigate.CredFile, instance, companion, user string) int {
	return slices.IndexFunc(f.Credentials, func(c aigate.Credential) bool {
		return c.Instance == instance && c.Companion == companion && c.User == user
	})
}

// encrypt encrypts plaintext to the gate and zeroes it (always).
func (s *aiCredStore) encrypt(plaintext []byte) (string, error) {
	defer clear(plaintext)
	r, err := s.recipient()
	if err != nil {
		return "", err
	}
	return aigate.Encrypt(r, plaintext)
}

// Put stores c (state active) with plaintext as its credential,
// replacing the person's entry for that companion. plaintext is zeroed.
func (s *aiCredStore) Put(c aigate.Credential, plaintext []byte) error {
	ct, err := s.encrypt(plaintext)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	c.State, c.Age = aigate.StateActive, ct
	next := s.cloneLocked()
	if i := credIndex(next, c.Instance, c.Companion, c.User); i >= 0 {
		next.Credentials[i] = c
	} else {
		next.Credentials = append(next.Credentials, c)
	}
	return s.commitLocked(next)
}

// MarkRevoking marks the person's entry revoking and drops its
// ciphertext (the gate then treats them as having none). Missing = nil.
func (s *aiCredStore) MarkRevoking(instance, companion, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	next := s.cloneLocked()
	i := credIndex(next, instance, companion, user)
	if i < 0 {
		return nil
	}
	next.Credentials[i].State, next.Credentials[i].Age = aigate.StateRevoking, ""
	return s.commitLocked(next)
}

// Remove drops the person's entry (after the app revoked it). Missing =
// nil.
func (s *aiCredStore) Remove(instance, companion, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	next := s.cloneLocked()
	i := credIndex(next, instance, companion, user)
	if i < 0 {
		return nil
	}
	next.Credentials = slices.Delete(next.Credentials, i, i+1)
	return s.commitLocked(next)
}

// Entries are the credentials' metadata — never the ciphertext.
func (s *aiCredStore) Entries() []aigate.Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadLocked() != nil {
		return nil
	}
	out := slices.Clone(s.file.Credentials)
	for i := range out {
		out[i].Age = ""
	}
	return out
}

// PutCallerSecret stores ref's (<instance>/<companion>) caller secret;
// plaintext is zeroed.
func (s *aiCredStore) PutCallerSecret(ref string, plaintext []byte) error {
	ct, err := s.encrypt(plaintext)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	next := s.cloneLocked()
	if i := slices.IndexFunc(next.CallerSecrets, func(c aigate.CallerSecret) bool { return c.Ref == ref }); i >= 0 {
		next.CallerSecrets[i].Age = ct
	} else {
		next.CallerSecrets = append(next.CallerSecrets, aigate.CallerSecret{Ref: ref, Age: ct})
	}
	return s.commitLocked(next)
}

// RemoveCallerSecret drops ref's caller secret. Missing = nil.
func (s *aiCredStore) RemoveCallerSecret(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	next := s.cloneLocked()
	i := slices.IndexFunc(next.CallerSecrets, func(c aigate.CallerSecret) bool { return c.Ref == ref })
	if i < 0 {
		return nil
	}
	next.CallerSecrets = slices.Delete(next.CallerSecrets, i, i+1)
	return s.commitLocked(next)
}

// HasCallerSecret reports whether ref has a caller secret entry.
func (s *aiCredStore) HasCallerSecret(ref string) bool {
	return slices.Contains(s.CallerSecretRefs(), ref)
}

// CallerSecretRefs are the refs with a caller secret entry.
func (s *aiCredStore) CallerSecretRefs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadLocked() != nil {
		return nil
	}
	var out []string
	for _, c := range s.file.CallerSecrets {
		out = append(out, c.Ref)
	}
	return out
}
