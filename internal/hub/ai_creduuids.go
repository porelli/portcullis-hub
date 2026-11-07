package hub

import (
	"fmt"
	"strings"

	"github.com/portcullis/hub/internal/aigate"
)

// The LLDAP account each app_token credential was minted for (scoped
// re-review N1): <data>/ai/credential-uuids.json, Hub-only (the gate's
// mcp-credentials.json carries no uuid, contract §15.4), 0600, atomic;
// "<instance>/<companion>/<user>" → {id, uuid}, ids and uuids only. A
// name deleted and re-created is another uuid: its entry is the former
// person's and is revoked, never handed to the new one.
const credUUIDsName = "credential-uuids.json"

type credUUIDFile struct {
	Version int                 `json:"version"`
	Entries map[string]credUUID `json:"entries"`
}

type credUUID struct {
	ID   string `json:"id"`
	UUID string `json:"uuid"`
}

func credUUIDKey(e aigate.Credential) string { return e.Instance + "/" + e.Companion + "/" + e.User }

// credUUIDsLocked reads the file (missing = empty). Caller holds
// aiStoreMu.
func (h *Hub) credUUIDsLocked() (map[string]credUUID, error) {
	var f credUUIDFile
	if err := h.readAIStore(credUUIDsName, &f); err != nil {
		return nil, err
	}
	if f.Version == 0 && f.Entries == nil {
		return map[string]credUUID{}, nil
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: version %d: fix or remove it", credUUIDsName, f.Version)
	}
	if f.Entries == nil {
		f.Entries = map[string]credUUID{}
	}
	return f.Entries, nil
}

// credUUIDs is the record (an unreadable file is an error: every entry
// is then unverifiable).
func (h *Hub) credUUIDs() (map[string]credUUID, error) {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	return h.credUUIDsLocked()
}

// recordCredUUID records that e was minted for LLDAP account uuid, and
// drops records of entries the store no longer has. An unreadable file
// is never replaced (an error).
func (h *Hub) recordCredUUID(e aigate.Credential, uuid string) error {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	rec, err := h.credUUIDsLocked()
	if err != nil {
		return err
	}
	entries, err := h.creds().EntriesErr()
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, c := range entries {
		keep[credUUIDKey(c)] = true
	}
	next := map[string]credUUID{credUUIDKey(e): {ID: e.ID, UUID: uuid}}
	for k, v := range rec {
		if _, set := next[k]; !set && keep[k] {
			next[k] = v
		}
	}
	return h.writeAIStore(credUUIDsName, credUUIDFile{Version: 1, Entries: next})
}

// credMintedFor: entry e was recorded as minted for LLDAP account
// current (same credential id, same non-empty uuid). No record, another
// id, an empty uuid on either side: false (unverifiable).
func credMintedFor(rec map[string]credUUID, e aigate.Credential, current string) bool {
	r, ok := rec[credUUIDKey(e)]
	return ok && r.ID == e.ID && r.UUID != "" && current != "" && strings.EqualFold(r.UUID, current)
}
