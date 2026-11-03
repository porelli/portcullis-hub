package hub

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Write-only secret settings (contract §13.10). The values live in
// <data>/settings/<id>/secrets.json (0600, atomic writes; the directory
// 0700), option key → value; state.yaml keeps only their metadata
// (state.SecretMeta). A value is never logged, audited, put on argv, in
// an error, an op record or an API answer: GET views show SecretView,
// and every op record / audit error of the instance is redacted with
// knownSecrets (redact, then clip).

// SecretView is a secret option as the panel shows it.
type SecretView struct {
	Set       bool       `json:"set"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	Generated bool       `json:"generated,omitempty"`
}

// Secret audit details (settings.change).
const (
	secretReplaced  = "replaced"
	secretGenerated = "generated"
	secretCleared   = "cleared"
)

// secretsDir is instance id's settings store directory.
func (h *Hub) secretsDir(id string) string { return filepath.Join(h.cfg.DataDir, "settings", id) }

// secretsPath is instance id's secrets store.
func (h *Hub) secretsPath(id string) string { return filepath.Join(h.secretsDir(id), "secrets.json") }

// secretValues are instance id's stored secret values by option key
// (missing store = none). Never log or echo them; used by the env, files
// and hooks.
func (h *Hub) secretValues(id string) (map[string]string, error) {
	if !templates.ValidID(id) {
		return map[string]string{}, nil
	}
	data, err := os.ReadFile(h.secretsPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the secrets store of %s: %w", id, err)
	}
	return parseSecrets(data)
}

// parseSecrets decodes a secrets store (or an archive's
// config/settings-secrets.json). Its errors never quote the content.
func parseSecrets(data []byte) (map[string]string, error) {
	out := map[string]string{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, errors.New("the secrets store is not a JSON object of strings")
	}
	for k := range out {
		if !templates.OptionKeyRe.MatchString(k) {
			return nil, errors.New("the secrets store has a key that is not an option key")
		}
	}
	return out, nil
}

// writeSecrets replaces instance id's store with vals (empty: the file is
// removed).
func (h *Hub) writeSecrets(id string, vals map[string]string) error {
	if len(vals) == 0 {
		if err := os.Remove(h.secretsPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing the secrets store of %s: %w", id, err)
		}
		return nil
	}
	if err := h.ensureSecretsDir(id); err != nil {
		return err
	}
	data, err := json.MarshalIndent(vals, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(h.secretsPath(id), data, 0600); err != nil {
		return fmt.Errorf("writing the secrets store of %s failed", id)
	}
	return nil
}

// ensureSecretsDir creates <data>/settings and <data>/settings/<id> as
// 0700 (the mode set once, when created: MkdirAll applies the umask; a
// failed chmod is logged, the store file itself is always 0600).
func (h *Hub) ensureSecretsDir(id string) error {
	for _, d := range []string{filepath.Dir(h.secretsDir(id)), h.secretsDir(id)} {
		if _, err := os.Stat(d); err == nil {
			continue
		}
		if err := os.Mkdir(d, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("secrets store directory of %s: %w", id, err)
		}
		if err := os.Chmod(d, 0700); err != nil {
			log.Printf("settings: chmod 0700 %s: %v", d, err)
		}
	}
	return nil
}

// removeSecrets removes instance id's settings store (delete, undone
// restores).
func (h *Hub) removeSecrets(id string) error {
	if !templates.ValidID(id) {
		return nil
	}
	return os.RemoveAll(h.secretsDir(id))
}

// knownSecrets are instance id's stored secret values (for redaction:
// op records, async ops, audit errors, hook output). A store that can't be
// read redacts nothing more (the env-based redaction still applies).
func (h *Hub) knownSecrets(id string) []string {
	vals, err := h.secretValues(id)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// redactValues replaces every secret in s with [redacted], longest first
// (a secret containing another is blanked whole). Callers clip after,
// never before.
func redactValues(s string, secrets []string) string {
	vals := append([]string(nil), secrets...)
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	for _, v := range vals {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}

// Generated-secret alphabets. ascii_printable is printable ASCII without
// space, ' and \ (an env value is single-quoted: envQuote refuses both).
var secretAlphabets = map[string]string{
	templates.CharsetHex:          "0123456789abcdef",
	templates.CharsetAlphanumeric: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	templates.CharsetASCIIPrintable: func() string {
		var b strings.Builder
		for c := byte('!'); c <= '~'; c++ {
			if c != '\'' && c != '\\' {
				b.WriteByte(c)
			}
		}
		return b.String()
	}(),
}

// generateSecret draws a value for g with crypto/rand (uniform over the
// charset's alphabet).
func generateSecret(g *templates.GenerateSpec) (string, error) {
	alpha, ok := secretAlphabets[g.Charset]
	if !ok {
		return "", fmt.Errorf("generate: unknown charset %q", g.Charset)
	}
	if g.Length < 1 {
		return "", fmt.Errorf("generate: length %d must be at least 1", g.Length)
	}
	n := big.NewInt(int64(len(alpha)))
	b := make([]byte, g.Length)
	for i := range b {
		x, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", fmt.Errorf("generate: %w", err)
		}
		b[i] = alpha[x.Int64()]
	}
	return string(b), nil
}

// secretViewsLocked are instance t's secret options as the panel shows
// them: set (with when, and whether generated) or not. Caller must hold
// mu.
func (h *Hub) secretViewsLocked(t *templates.Template) map[string]SecretView {
	meta := h.st.Settings[t.ID].Secrets
	out := map[string]SecretView{}
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.Type != templates.TypeSecret {
			continue
		}
		v := SecretView{}
		if m, ok := meta[o.Key]; ok {
			at := m.UpdatedAt
			v = SecretView{Set: true, UpdatedAt: &at, Generated: m.Generated}
		}
		out[o.Key] = v
	}
	return out
}

// secretOptionEnvNames are the env names t's secret options own.
func secretOptionEnvNames(t *templates.Template) map[string]bool {
	out := map[string]bool{}
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].Type != templates.TypeSecret {
			continue
		}
		for _, n := range opts[i].EnvNames() {
			out[n] = true
		}
	}
	return out
}

// optionEnvOwners maps every env name of t's options to its option key.
func optionEnvOwners(t *templates.Template) map[string]string {
	out := map[string]string{}
	opts := t.Manifest.Options()
	for i := range opts {
		for _, n := range opts[i].EnvNames() {
			out[n] = opts[i].Key
		}
	}
	return out
}

// blankEnvNames is an .env file with the values of names emptied (KEY=),
// and of every variable whose value is one of secrets (an instance whose
// template doesn't resolve: its secret options' names are unknown), every
// other line kept byte for byte: a backup's config/env carries no secret
// (they are in config/settings-secrets.json only).
func blankEnvNames(data []byte, names map[string]bool, secrets map[string]string) []byte {
	names = maps.Clone(names)
	if names == nil {
		names = map[string]bool{}
	}
	stored := map[string]bool{}
	for _, v := range secrets {
		if v != "" {
			stored[v] = true
		}
	}
	for k, v := range parseEnv(data) {
		if stored[v] {
			names[k] = true
		}
	}
	if len(names) == 0 {
		return data
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && !strings.HasPrefix(k, "#") && names[k] {
			lines[i] = k + "="
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// archiveSecrets are the secret values a staged archive holds: its
// secrets store and the secret-looking values of its env (t: its
// template, may be nil). For redaction only.
func archiveSecrets(t *templates.Template, sb *staged) []string {
	var out []string
	if sb.secrets != nil {
		if vals, err := parseSecrets(sb.secrets); err == nil {
			for _, v := range vals {
				if v != "" {
					out = append(out, v)
				}
			}
		}
	}
	if sb.env != nil {
		out = append(out, envSecrets(t, parseEnv(sb.env))...)
	}
	return out
}

// writeArchivedSecrets writes an archive's secrets (nil = none) into
// instance id's store as they are (an instance whose template doesn't
// resolve: nothing to filter them by).
func (h *Hub) writeArchivedSecrets(id string, data []byte) error {
	vals := map[string]string{}
	if data != nil {
		var err error
		if vals, err = parseSecrets(data); err != nil {
			return err
		}
	}
	return h.writeSecrets(id, vals)
}

// restoreSecretsLocked puts an archive's secrets (data: its
// config/settings-secrets.json, nil = none) into instance t's store,
// keeping only t's declared secret options, and makes the metadata in
// state match (a key with a value has its meta, one without has none).
// regenerate (a restore into a new id): every stored secret whose option
// declares generate gets a new value, so the copies don't share it.
// Caller must hold mu (write); the caller saves state.
func (h *Hub) restoreSecretsLocked(t *templates.Template, data []byte, regenerate bool) error {
	vals := map[string]string{}
	if data != nil {
		var err error
		if vals, err = parseSecrets(data); err != nil {
			return err
		}
	}
	s := h.st.Settings[t.ID]
	meta := map[string]state.SecretMeta{}
	now := time.Now().UTC()
	keep := map[string]string{}
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.Type != templates.TypeSecret {
			continue
		}
		v, ok := vals[o.Key]
		if !ok || v == "" {
			continue
		}
		m, had := s.Secrets[o.Key]
		if !had {
			m = state.SecretMeta{UpdatedAt: now}
		}
		if regenerate && o.Generate != nil {
			g, err := generateSecret(o.Generate)
			if err != nil {
				return err
			}
			v, m = g, state.SecretMeta{UpdatedAt: now, Generated: true}
		}
		keep[o.Key], meta[o.Key] = v, m
	}
	if err := h.writeSecrets(t.ID, keep); err != nil {
		return err
	}
	s.Secrets = meta
	if len(s.Secrets) == 0 {
		s.Secrets = nil
	}
	if s.IsZero() {
		delete(h.st.Settings, t.ID)
	} else {
		h.st.Settings[t.ID] = s
	}
	return nil
}
