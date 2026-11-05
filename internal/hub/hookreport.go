package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Hook reports (contract §13.8, F32): a hook may print one
// "PORTCULLIS-REPORT <json>" line. The Hub reads it as untrusted input,
// from the redacted output: settings.ParseHookReport (strict JSON, one
// line, bounded lists and strings), then findings whose subject isn't in
// the population (for name_refused: isn't a share name the instance's
// settings hold) and folders of an unknown option are dropped. The last
// accepted report is kept with its receive time in
// <data>/settings/<id>/hook-report.json (0600) for the File sharing tab
// and the doctor; a malformed one is logged and ignored (the hook unit
// stays OK). A report never drives revocation or authorization; the
// owner uids it lists feed the person-id pools' seen owners (F8). The
// line never reaches an op record or a unit message.

// HookReportPrefix starts a hook's report line.
const HookReportPrefix = "PORTCULLIS-REPORT "

// StoredHookReport is hook-report.json: the last accepted report, the
// hook that printed it and when it arrived.
type StoredHookReport struct {
	Hook       string              `json:"hook"`
	ReceivedAt time.Time           `json:"received_at"`
	Report     settings.HookReport `json:"report"`
}

func (h *Hub) hookReportPath(id string) string {
	return filepath.Join(h.secretsDir(id), "hook-report.json")
}

// HookReport is instance id's last accepted hook report (false: none, or
// unreadable — logged).
func (h *Hub) HookReport(id string) (*StoredHookReport, bool) {
	if !templates.ValidID(id) {
		return nil, false
	}
	b, err := os.ReadFile(h.hookReportPath(id))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("settings: %s: reading the hook report: %v", id, err)
		}
		return nil, false
	}
	var r StoredHookReport
	if err := json.Unmarshal(b, &r); err != nil {
		log.Printf("settings: %s: the stored hook report is unreadable (%v): ignored", id, err)
		return nil, false
	}
	return &r, true
}

// hasReportLine: out holds a line starting with HookReportPrefix.
func hasReportLine(out []byte) bool {
	for _, l := range bytes.Split(out, []byte{'\n'}) {
		if bytes.HasPrefix(l, []byte(HookReportPrefix)) {
			return true
		}
	}
	return false
}

// stripReportLines is s without its report lines (op records, unit
// messages and logs never carry them).
func stripReportLines(s string) string {
	if !strings.Contains(s, HookReportPrefix) {
		return s
	}
	lines := strings.Split(s, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if !strings.HasPrefix(strings.TrimLeft(l, "\r"), HookReportPrefix) {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "\n")
}

// acceptHookReport reads hook hk's report from its (redacted) output out:
// parsed, filtered, stored, its owner uids noted. Every refusal is logged
// and changes nothing. Never under mu (it reads the directory).
func (h *Hub) acceptHookReport(ctx context.Context, t *templates.Template, hk templates.Hook, out []byte) {
	if !hasReportLine(out) {
		return
	}
	rep, err := settings.ParseHookReport(out)
	if err != nil {
		log.Printf("settings: %s: hook %s: report ignored: %v", t.ID, hk.Name, err)
		return
	}
	m, err := h.membership(ctx)
	if err != nil {
		log.Printf("settings: %s: hook %s: report ignored: its subjects can't be checked (%v)", t.ID, hk.Name, err)
		return
	}
	h.mu.RLock()
	live := h.findLocked(t.ID)
	if live == nil {
		h.mu.RUnlock()
		return
	}
	pop := map[string]bool{}
	for _, p := range h.populationLocked(live, m).People {
		pop[p.User] = true
	}
	shares := map[string]bool{}
	paths := map[string]bool{}
	s := h.st.Settings[t.ID]
	opts := live.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.EffectiveScope() != templates.ScopeInstance {
			continue
		}
		switch o.Type {
		case templates.TypePath:
			paths[o.Key] = true
		case templates.TypeString:
			if v, ok := h.effectiveValue(live, o, s); ok {
				if str, _ := v.(string); str != "" {
					shares[str] = true
				}
			}
		}
	}
	var pools []string
	for _, o := range personIDOptions(live) {
		if !slices.Contains(pools, o.Pool) {
			pools = append(pools, o.Pool)
		}
	}
	h.mu.RUnlock()

	kept := settings.HookReport{Version: rep.Version, Findings: []settings.HookFinding{}, Folders: []settings.HookFolder{}}
	var owners []int
	dropped := 0
	for _, f := range rep.Findings {
		ok := pop[f.Subject]
		if f.Code == "name_refused" {
			// A share name, or a population member's username the app
			// refuses (B-M2/D-M1: an Info naming the user).
			ok = shares[f.Subject] || pop[f.Subject]
			if !shares[f.Subject] && pop[f.Subject] {
				f.Severity = "info"
			}
		}
		if f.Option != "" && !paths[f.Option] {
			ok = false
		}
		if !ok {
			dropped++
			continue
		}
		kept.Findings = append(kept.Findings, f)
		if f.UID != nil {
			owners = append(owners, int(*f.UID))
		}
	}
	for _, f := range rep.Folders {
		if !paths[f.Option] {
			dropped++
			continue
		}
		kept.Folders = append(kept.Folders, f)
		owners = append(owners, int(f.UID))
	}
	if dropped > 0 {
		log.Printf("settings: %s: hook %s: report: %d entries about unknown people, shares or options dropped", t.ID, hk.Name, dropped)
	}
	b, err := json.MarshalIndent(StoredHookReport{Hook: hk.Name, ReceivedAt: time.Now().UTC(), Report: kept}, "", "  ")
	if err == nil {
		if err = os.MkdirAll(h.secretsDir(t.ID), 0700); err == nil {
			err = fsutil.WriteFileAtomic(h.hookReportPath(t.ID), append(b, '\n'), 0600)
		}
	}
	if err != nil {
		log.Printf("settings: %s: hook %s: storing the report failed: %v", t.ID, hk.Name, err)
	}
	if len(owners) == 0 {
		return
	}
	for _, p := range pools {
		if err := h.NoteSeenOwners(p, owners); err != nil {
			log.Printf("settings: %s: hook %s: noting the report's owners in pool %s: %v", t.ID, hk.Name, p, err)
		}
	}
}
