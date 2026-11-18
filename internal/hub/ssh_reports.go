package hub

// Host reports (contract §18.11, plan C40): the last report per host in
// hub_data/ssh/hosts/<id>.json (0600). A report is untrusted: strictly
// decoded (≤ 256 KiB), bounded, never executed, never used as a path (only
// the host id, already in its grammar, names the file). Findings are
// derived when read.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/fsutil"
)

// StoredReport is a report as the Hub keeps it.
type StoredReport struct {
	Received time.Time     `json:"received"`
	Report   cliapi.Report `json:"report"`
}

const maxReportString = 256

func reportStringOK(s string) bool {
	return len(s) <= maxReportString && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

// validReport bounds every field (the schema is cliapi's, strict).
func validReport(hostID string, r cliapi.Report) error {
	switch {
	case r.Version != cliapi.ReportVersion:
		return errors.New("version")
	case r.HostID != hostID:
		return errors.New("another host's report")
	case len(r.Files) > 4096, len(r.Findings) > 1024, len(r.Effective) > 8:
		return errors.New("too many entries")
	case !reportStringOK(r.SSHDVersion) || !reportStringOK(r.Error):
		return errors.New("bad string")
	case r.AuthorizedKeysShared < 0 || r.Logins.Portcullis < 0 || r.Logins.Breakglass < 0:
		return errors.New("negative count")
	case len(r.Accounts.SudoCapable) > cliapi.MaxSudoChecked:
		return errors.New("too many sudo accounts")
	}
	for _, a := range r.Accounts.SudoCapable {
		if !cliapi.ValidAccount(a) {
			return errors.New("bad sudo account")
		}
	}
	for k, v := range r.Files {
		if !reportStringOK(k) || !reportStringOK(v) {
			return errors.New("bad string")
		}
	}
	for k, m := range r.Effective {
		if !reportStringOK(k) || len(m) > 32 {
			return errors.New("bad effective block")
		}
		for kk, vv := range m {
			if !reportStringOK(kk) || !reportStringOK(vv) {
				return errors.New("bad string")
			}
		}
	}
	for _, f := range r.Findings {
		if !reportStringOK(f.Kind) || !reportStringOK(f.Severity) || !reportStringOK(f.Subject) || !reportStringOK(f.Detail) {
			return errors.New("bad string")
		}
	}
	for _, l := range [][]string{r.Accounts.Present, r.Accounts.Missing, r.Accounts.Locked, r.Accounts.Removed} {
		if len(l) > 100000 {
			return errors.New("too many accounts")
		}
		for _, a := range l {
			if !reportStringOK(a) {
				return errors.New("bad string")
			}
		}
	}
	if !reportStringOK(r.Logins.BreakglassLast.Time) || !reportStringOK(r.Logins.BreakglassLast.From) {
		return errors.New("bad string")
	}
	return nil
}

func (h *Hub) reportPath(id string) string { return filepath.Join(h.sshDir(), "hosts", id+".json") }

// HostReport stores host hostID's report (already signature-checked) and
// audits each new finding (ssh.host.drift) and each removal it confirms.
func (h *Hub) HostReport(ctx context.Context, hostID string, r cliapi.Report) error {
	if !cliapi.ValidHostID(hostID) {
		return refusal(http.StatusForbidden, TextRemoved, "bad host id")
	}
	if err := validReport(hostID, r); err != nil {
		return refusal(http.StatusBadRequest, "malformed report", "report: "+err.Error())
	}
	prev, _ := h.LastHostReport(hostID)
	raw, err := json.MarshalIndent(StoredReport{Received: h.sshrt.clock().UTC(), Report: r}, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.reportPath(hostID)), 0o700); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(h.reportPath(hostID), raw, 0o600); err != nil {
		return err
	}
	had := map[string]bool{}
	if prev != nil {
		for _, f := range prev.Report.Findings {
			had[f.Kind+"\x00"+f.Subject+"\x00"+f.Detail] = true
		}
	}
	for _, f := range r.Findings {
		if !had[f.Kind+"\x00"+f.Subject+"\x00"+f.Detail] && f.Kind == cliapi.FindingDrift {
			h.auditSSH("-", "ssh.host.drift", hostID, clip(f.Subject, 128)+": "+clip(f.Detail, 128), nil)
		}
	}
	// RR-H1: which accounts can reach root there; a change recompiles
	// (grants of those accounts become privileged, bundles mark them).
	capable := slices.Clone(r.Accounts.SudoCapable)
	slices.Sort(capable)
	if !r.Accounts.SudoChecked {
		capable = nil
	}
	h.mu.Lock()
	sudoChanged := false
	if hst, ok := h.st.SSH.Hosts[hostID]; ok && (hst.SudoChecked != r.Accounts.SudoChecked || !slices.Equal(hst.SudoCapable, capable)) {
		hst.SudoChecked, hst.SudoCapable = r.Accounts.SudoChecked, capable
		h.st.SSH.Hosts[hostID] = hst
		h.saveLocked()
		sudoChanged = true
	}
	h.mu.Unlock()
	if sudoChanged {
		for _, a := range capable {
			if h.SSHSharedAccount(a) {
				h.auditSSH("-", "ssh.host.sudo_account", hostID, "shared account "+a+" has sudo there: its grants are privileged", nil)
			}
		}
		h.TriggerSSHCompile()
	}
	// Removals the report confirms leave the bundle's remove list.
	if len(r.Accounts.Removed) > 0 {
		h.mu.Lock()
		if hst, ok := h.st.SSH.Hosts[hostID]; ok {
			keep := hst.RemoveAccounts[:0]
			for _, a := range hst.RemoveAccounts {
				if !slices.Contains(r.Accounts.Removed, a) {
					keep = append(keep, a)
				}
			}
			hst.RemoveAccounts = keep
			h.st.SSH.Hosts[hostID] = hst
			h.saveLocked()
		}
		h.mu.Unlock()
		h.TriggerSSHCompile()
	}
	return nil
}

// LastHostReport is hostID's stored report (nil when none).
func (h *Hub) LastHostReport(hostID string) (*StoredReport, error) {
	if !cliapi.ValidHostID(hostID) {
		return nil, errors.New("bad host id")
	}
	raw, err := os.ReadFile(h.reportPath(hostID))
	if err != nil {
		return nil, err
	}
	var s StoredReport
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
