package hub

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/portcullis/hub/internal/templates"
)

// The Portcullis MCP's one redactor (contract §15.10, preflight G40):
// every tool result is redacted with the union of every instance's
// redaction set (redactionSetErr: stored secret settings, secret-looking
// and generated env values, the core .env's, the NT hashes, every model
// provider secret), then clipped. The httpapi layer adds the Hub's file
// secrets and caches the whole set under ToolRedactionKey.

// toolRedactionIDs are every instance id the Hub may hold secrets for:
// every instance view, and every id that has an env file or a settings
// store on disk (an instance whose template is gone still has them).
func (h *Hub) toolRedactionIDs() []string {
	seen := map[string]bool{}
	h.mu.RLock()
	for i := range h.instances {
		seen[h.instances[i].ID] = true
	}
	h.mu.RUnlock()
	if es, err := os.ReadDir(filepath.Join(h.cfg.DataDir, "env")); err == nil {
		for _, e := range es {
			if id, ok := strings.CutSuffix(e.Name(), ".env"); ok && templates.ValidID(id) {
				seen[id] = true
			}
		}
	}
	if es, err := os.ReadDir(filepath.Join(h.cfg.DataDir, "settings")); err == nil {
		for _, e := range es {
			if e.IsDir() && templates.ValidID(e.Name()) {
				seen[e.Name()] = true
			}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// ToolRedactionSet is the union of every instance's redaction set
// (redactionSetErr). err: some set exists but can't be read whole — the
// caller then hides the result (fail closed).
func (h *Hub) ToolRedactionSet() ([]string, error) {
	return h.redactionSets(h.toolRedactionIDs()...)
}

// ToolRedactionKey changes whenever ToolRedactionSet may: it names every
// file the set is read from (path, size, mtime, inode — a stat each,
// never the content) and, per instance, the template inputs that decide
// which values count (generated env keys, person_secret options).
func (h *Hub) ToolRedactionKey() string {
	var b strings.Builder
	stat := func(p string) {
		fi, err := os.Stat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(&b, "%s:-\n", p)
		case err != nil:
			fmt.Fprintf(&b, "%s:err:%v\n", p, err)
		default:
			var ino uint64
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				ino = uint64(st.Ino)
			}
			fmt.Fprintf(&b, "%s:%d:%d:%d:%v\n", p, fi.Size(), fi.ModTime().UnixNano(), ino, fi.Mode())
		}
	}
	stat(filepath.Join(h.cfg.ProjectDir, ".env"))
	stat(h.providerSecretsPath())
	if h.secretsErr != nil {
		fmt.Fprintf(&b, "secrets-volume:%v\n", h.secretsErr)
	}
	for _, id := range h.toolRedactionIDs() {
		fmt.Fprintf(&b, "id %s\n", id)
		stat(h.envPath(id))
		stat(h.secretsPath(id))
		t := h.Template(id)
		if t == nil {
			continue
		}
		for _, e := range t.Manifest.Env {
			if e.Generate != "" && e.Generate != "none" {
				fmt.Fprintf(&b, "gen %s\n", e.Key)
			}
		}
		for _, o := range personSecretOptions(t) {
			fmt.Fprintf(&b, "person_secret %s\n", o.Key)
			if rel, err := secretDirRel(id, o.Key); err == nil && h.cfg.SecretsDir != "" {
				stat(filepath.Join(h.cfg.SecretsDir, filepath.FromSlash(rel)))
			}
		}
	}
	return b.String()
}

// RedactValues replaces every one of secrets in s (and its JSON string
// forms) with [redacted] (redactValues). Redact, then clip.
func RedactValues(s string, secrets []string) string { return redactValues(s, secrets) }
