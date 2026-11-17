package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
)

// Metrics discovery (contract §19.8, P7): mail_slot/mail-targets.json
// (file_sd), written in place on every wire, unwire and Hub start: []
// when nothing is wired or the provider isn't in normal mode (so the
// generic up == 0 alert never fires for an empty slot), else the
// provider's metrics target and, with server_metrics, the server's.

const mailTargetsFile = "mail-targets.json"

type mailTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// mailTargetsLocked is the file_sd content. Caller must hold mu (read).
func (h *Hub) mailTargetsLocked() []mailTarget {
	out := []mailTarget{}
	p := h.st.Mail.Provider
	if p == nil || h.mailModeLocked(p.Instance) != mailNormal || (h.st.Mail.Held != nil && h.st.Mail.Held.Stopped != nil) {
		return out
	}
	_, m := h.mailWiredLocked()
	if m == nil {
		return out
	}
	out = append(out, mailTarget{Targets: []string{mailMetricsAlias + ":" + strconv.Itoa(m.Metrics.Port)}, Labels: map[string]string{"service": "provider"}})
	if sm := m.ServerMetrics; sm != nil {
		out = append(out, mailTarget{Targets: []string{mailServerMetricsAlias + ":" + strconv.Itoa(sm.Port)},
			Labels: map[string]string{"service": "server", "__metrics_path__": sm.Path}})
	}
	return out
}

// writeMailTargets writes mail-targets.json (a failure is logged:
// Prometheus keeps the last file).
func (h *Hub) writeMailTargets() {
	if h.cfg.MailSlotDir == "" {
		return
	}
	h.mu.RLock()
	b, err := json.Marshal(h.mailTargetsLocked())
	h.mu.RUnlock()
	if err != nil {
		return
	}
	r, err := os.OpenRoot(h.cfg.MailSlotDir)
	if err != nil {
		log.Printf("mail: the mail_slot volume: %v", err)
		return
	}
	defer r.Close()
	if err := writeInPlace(r, mailTargetsFile, append(b, '\n'), -1); err != nil {
		log.Printf("mail: writing %s: %v", mailTargetsFile, err)
	}
}

// HostMailStatusView is GET /host/mail/status (contract §19.10): the
// Hub's view, read by `./portcullis mail status` (core interface item
// 4: wired, reachable, void_owed, held, checks.checks[].severity).
type HostMailStatusView struct {
	Slot              string                       `json:"slot"`
	Wired             bool                         `json:"wired"`
	Instance          string                       `json:"instance"`
	Template          string                       `json:"template"`
	Mode              string                       `json:"mode"`
	Reachable         bool                         `json:"reachable"`
	Provider          *mailprovider.StatusProvider `json:"provider"`
	Generation        int                          `json:"generation"`
	AppliedGeneration int                          `json:"applied_generation"`
	// VoidOwed and Held are null or an object, never false (core
	// interface fix round 1, item 4).
	VoidOwed *MailVoidView        `json:"void_owed"`
	Held     *state.MailHold      `json:"held"`
	Checks   *mailprovider.Checks `json:"checks"`
}

// HostMailStatus is the host status view (the provider read with a
// bound; unreachable is a fact, not an error).
func (h *Hub) HostMailStatus(ctx context.Context) HostMailStatusView {
	v := HostMailStatusView{Slot: "closed", Mode: mailUnwired.String()}
	if h.mailOn() {
		v.Slot = "open"
	}
	h.mu.RLock()
	if p := h.st.Mail.Provider; p != nil {
		v.Wired, v.Instance, v.Template = true, p.Instance, p.Template
		v.Mode = h.mailModeTextLocked(p.Instance)
	}
	v.Generation = h.st.Mail.Generation
	v.VoidOwed = h.mailVoidViewLocked()
	if hd := h.st.Mail.Held; hd != nil {
		c := *hd
		v.Held = &c
	}
	h.mu.RUnlock()
	api := h.mailClient()
	if api == nil {
		return v
	}
	sctx, cancel := context.WithTimeout(ctx, mailCallTimeout)
	defer cancel()
	st, err := api.State(sctx)
	if err != nil || !st.Bootstrap {
		return v
	}
	v.Reachable, v.AppliedGeneration = true, st.AppliedGeneration
	if s, err := api.Status(sctx); err == nil {
		p := s.Provider
		v.Provider = &p
	}
	if ch, err := api.Checks(sctx, false); err == nil {
		v.Checks = &ch
	}
	return v
}

// spkiHexRe is one SPKI sha256 (64 lowercase hex).
var spkiHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HostMailTLS is POST /host/mail/tls {spki_sha256, not_after} (contract
// §19.3): the certificate recorded with the timer's visit, then, while a
// provider is wired and serving, the provider's reload; answers the SPKI
// it then serves ("" when nothing reloaded). A serving SPKI outside the
// list is logged (its cert check reports it).
func (h *Hub) HostMailTLS(ctx context.Context, spki []string, notAfter time.Time) (string, error) {
	if len(spki) < 1 || len(spki) > 2 {
		return "", statusErr(http.StatusBadRequest, "spki_sha256 must list 1 or 2 SPKIs")
	}
	for _, k := range spki {
		if !spkiHexRe.MatchString(k) {
			return "", statusErr(http.StatusBadRequest, "an SPKI must be 64 lowercase hex")
		}
	}
	if notAfter.IsZero() {
		return "", statusErr(http.StatusBadRequest, "not_after is required")
	}
	now := h.mailNow().UTC()
	na := notAfter.UTC()
	h.mu.Lock()
	prev := h.st.Mail.TLS
	h.st.Mail.TLS = state.MailTLS{SPKISHA256: append([]string{}, spki...), NotAfter: &na, SeenAt: &now}
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail.TLS = prev
		h.mu.Unlock()
		return "", err
	}
	h.mu.Unlock()
	h.TriggerMailSync() // MailState v2 carries the SPKIs
	// A success only when the provider serves one of the posted SPKIs
	// (core interface fix round 1, item 2: core drops a TLSA record only
	// on it): not running, a failed reload or another SPKI is a failure
	// (the certificate stays recorded).
	api := h.mailClient()
	if api == nil {
		return "", statusErr(http.StatusServiceUnavailable, "the certificate is recorded, but no mail provider is serving: nothing reloaded")
	}
	rctx, cancel := context.WithTimeout(ctx, mailCallTimeout)
	defer cancel()
	serving, err := api.TLSReload(rctx, spki)
	if err != nil {
		return "", statusErr(http.StatusServiceUnavailable, "the mail provider didn't reload its certificate: %v", err)
	}
	if !slices.Contains(spki, serving) {
		log.Printf("mail: the provider serves SPKI %q, not one of the mail certificate's", mailprovider.Shape(serving, 80))
		return "", statusErr(http.StatusBadGateway, "the mail provider serves another certificate (SPKI %q), not one of the posted ones", mailprovider.Shape(serving, 80))
	}
	return serving, nil
}

// HostMailTest is POST /host/mail/test {to}: the provider's test message.
func (h *Hub) HostMailTest(ctx context.Context, to string) (string, error) {
	api := h.mailClient()
	if api == nil {
		return "", errMailDown
	}
	tctx, cancel := context.WithTimeout(ctx, mailCallTimeout)
	defer cancel()
	q, err := api.Test(tctx, to)
	if err != nil {
		var ae *mailprovider.APIError
		if errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 {
			return "", statusErr(ae.Status, "%s", ae.Msg)
		}
		return "", statusErr(http.StatusServiceUnavailable, "the mail provider can't send the test: %v", err)
	}
	return q, nil
}

// HostMailBackup is POST /host/mail/backup (contract §19.11): an
// instance backup of the wired provider with reason core, waited for;
// answers the archive's path relative to the backups directory. While a
// void is owed or the provider is held it comes back in void mode (the
// render), or stays stopped.
func (h *Hub) HostMailBackup() (string, error) {
	h.mu.RLock()
	p := h.st.Mail.Provider
	h.mu.RUnlock()
	if p == nil {
		return "", statusErr(http.StatusConflict, "no mail provider is wired")
	}
	var entry *BackupEntry
	_, _, err := h.runOpSync(p.Instance, OpBackup, directory.Human(HostActor), []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		var berr error
		entry, berr = h.backupInstanceReason(ctx, p.Instance, directory.Human(HostActor), ready, BackupCore)
		if entry != nil {
			return map[string]string{"archive": entry.Archive}, nil, berr
		}
		return nil, nil, berr
	})
	if err != nil {
		return "", err
	}
	return entry.Archive, nil
}

// mailRestorePendingFile (core interface C1): core writes
// hub_data/mail-restore-pending (the archive's name) before the Hub
// starts in a core restore; while it exists the wired provider is never
// started (no void, no up: its volumes come back first, Ruling R-C1).
// `hub mail restore`'s op passes it and removes it once it succeeded.
const mailRestorePendingFile = "mail-restore-pending"

var errMailRestorePending = statusErr(http.StatusConflict, "a core restore of the mail provider is pending: the provider starts after `hub mail restore`")

// mailRestoreCommitKey marks the one up that may pass the restore hold:
// a restore's final start, after applyRestore restored the volumes. Its
// value is the instance.
type mailRestoreCommitKey struct{}

// withMailRestoreCommit is ctx carrying id's restore-commit token.
func withMailRestoreCommit(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, mailRestoreCommitKey{}, id)
}

// mailRestoreCommitted: ctx is id's restore commit.
func mailRestoreCommitted(ctx context.Context, id string) bool {
	v, _ := ctx.Value(mailRestoreCommitKey{}).(string)
	return v != "" && v == id
}

// mailRestorePending: the C1 hold is on (an unreadable data directory
// holds too: fail closed).
func (h *Hub) mailRestorePending() bool {
	if h.cfg.DataDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(h.cfg.DataDir, mailRestorePendingFile))
	return err == nil || !os.IsNotExist(err)
}

// mailRestorePendingArchive is the archive the pending core restore
// names (the file is the archive's name and a newline; core interface
// fix round 1, item 5). ok false: no file. An unreadable or malformed
// file is an error (the hold stays).
func (h *Hub) mailRestorePendingArchive() (name string, ok bool, err error) {
	if h.cfg.DataDir == "" {
		return "", false, nil
	}
	f, err := os.OpenInRoot(h.cfg.DataDir, mailRestorePendingFile)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", true, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return "", true, err
	}
	s, cut := strings.CutSuffix(string(b), "\n")
	if !cut || !archiveRe.MatchString(s) {
		return "", true, fmt.Errorf("%s isn't an archive name and a newline", mailRestorePendingFile)
	}
	return s, true, nil
}

// HostMailRestore is POST /host/mail/restore {archive}: the wired
// provider restored from that archive in the background (a void is owed
// before its volumes are replaced; restoreSteps). The C1 hold is removed
// as the op starts, before the restore's own up.
func (h *Hub) HostMailRestore(archive string) (*AsyncOp, error) {
	h.mu.RLock()
	p := h.st.Mail.Provider
	h.mu.RUnlock()
	if p == nil {
		return nil, statusErr(http.StatusConflict, "no mail provider is wired")
	}
	id := p.Instance
	// The name first (never a filesystem call on an unchecked path: no
	// traversal, no existence oracle), and only the provider's own.
	if mm := archiveRe.FindStringSubmatch(archive); mm == nil || mm[1] != id {
		return nil, statusErr(http.StatusBadRequest, "archive must be %s/<YYYYMMDDTHHMMSSZ>.tar (an archive of the wired provider)", id)
	}
	// A pending core restore restores exactly the archive it names.
	if want, pending, err := h.mailRestorePendingArchive(); err != nil {
		return nil, statusErr(http.StatusConflict, "the pending core restore can't be read (%v): the provider stays stopped", err)
	} else if pending && want != archive {
		return nil, statusErr(http.StatusConflict, "the pending core restore names %s, not %s", want, archive)
	}
	if err := h.archiveExists(archive); err != nil {
		return nil, err
	}
	actor := directory.Human(HostActor)
	return h.startAsync(id, OpRestore, actor, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		// Only the restore's final start, after its volumes came back,
		// passes the hold (applyRestore's commit token); the hold goes
		// only once the restore succeeded (R2-N4): a failed one keeps it,
		// so no empty store goes live.
		res, err := h.restoreInstance(ctx, id, archive, actor, ready)
		if err == nil {
			if rerr := os.Remove(filepath.Join(h.cfg.DataDir, mailRestorePendingFile)); rerr != nil && !os.IsNotExist(rerr) {
				err = fmt.Errorf("the provider is restored, but removing %s failed: %w", mailRestorePendingFile, rerr)
			}
			h.kickMailVoid() // the owed void's normal up, now the hold is gone
		}
		return restoreResult(res, archive, ""), restoreWarnings(res), err
	})
}

// HostMailOpView is GET /host/mail/op (core interface H6): one op's
// state with running and ok always present.
type HostMailOpView struct {
	OpID     string `json:"op_id"`
	Op       string `json:"op"`
	Instance string `json:"instance"`
	Running  bool   `json:"running"`
	OK       bool   `json:"ok"`
	Error    string `json:"error"`
	Status   int    `json:"status"`
}

// HostMailOp is instance's record of op opID (nil: none).
func (h *Hub) HostMailOp(instance, opID string) *HostMailOpView {
	r := h.OpByID(instance, opID)
	if r == nil {
		return nil
	}
	return &HostMailOpView{OpID: r.OpID, Op: r.Op, Instance: instance, Running: r.Running, OK: r.OK && !r.Running, Error: r.Error, Status: r.Status}
}

// MailRulesView is the rule context core passes to dns-tool with the
// main set (core interface H5/M6).
type MailRulesView struct {
	RelayInclude string `json:"relay_include"`
	DMARCFloor   string `json:"dmarc_floor"`
	Draining     bool   `json:"draining"`
}

// HostMailDNSRules is the main domain's rule context.
func (h *Hub) HostMailDNSRules() MailRulesView {
	h.mu.RLock()
	c := h.mailRuleContextLocked(h.cfg.Domain, true)
	h.mu.RUnlock()
	return MailRulesView{RelayInclude: c.RelayInclude, DMARCFloor: c.DMARCFloor, Draining: c.Draining}
}
