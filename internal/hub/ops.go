package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Lifecycle operations recorded per app.
const (
	OpEnable  = "enable"
	OpDisable = "disable"
	OpRestart = "restart"
	OpStart   = "start"   // drift: compose up an enabled app
	OpApply   = "apply"   // drift: regenerate the override and compose up
	OpStop    = "stop"    // drift: compose down a project that is not enabled
	OpHosts   = "hosts"   // hostname change (SetHosts): Keycloak, files, restart
	OpDelete  = "delete"  // guarded delete (a failure leaves it "deleting": retry)
	OpRestore = "restore" // restore from a backup (a failure puts the pre-restore backup back)
	OpReload  = "reload"  // a settings delivery's reload signal (deliver_reload.go)
	OpHook    = "hook"    // a settings hook run (deliver_hooks.go)
	// OpCredentials: a revocation that could not be applied live
	// stopped the instance (credentials.go, contract §13.16 step 3).
	OpCredentials = "credentials"
)

// OpRecord is an app's last lifecycle operation, kept in
// <data>/ops/<id>.json so a failure stays explainable after a reload —
// also for an app that is not enabled (a failed enable).
type OpRecord struct {
	Op     string    `json:"op"`
	At     time.Time `json:"at"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
	Output string    `json:"output,omitempty"` // tail of compose's output (secrets redacted)
	Hint   string    `json:"hint,omitempty"`
	// RolledBack: a failed enable was undone (compose down: containers
	// and network removed, volumes kept).
	RolledBack bool `json:"rolled_back,omitempty"`
	// Background operations (backup, restore, delete; AsyncOp): OpID
	// names the request, Running is true until it finished (At = start
	// time while running), Result its outcome (archive, backup,
	// pre_restore_backup, instance), Warnings as the synchronous answer
	// had them, Status the HTTP status a failure stands for, Actor the
	// user who started it (actor.User only, never via/client).
	OpID     string            `json:"op_id,omitempty"`
	Running  bool              `json:"running,omitempty"`
	Result   map[string]string `json:"result,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	Status   int               `json:"status,omitempty"`
	Actor    string            `json:"actor,omitempty"`
}

// OpError is a failed lifecycle operation as the API returns it: the
// message plus compose's output and a hint. It unwraps to the cause (for
// the HTTP status).
type OpError struct {
	Record OpRecord
	Err    error
}

func (e *OpError) Error() string { return e.Record.Error }
func (e *OpError) Unwrap() error { return e.Err }

func (h *Hub) opsDir() string          { return filepath.Join(h.cfg.DataDir, "ops") }
func (h *Hub) opPath(id string) string { return filepath.Join(h.opsDir(), id+".json") }

// hostsOpPath keeps the last hostname change's record (OpHosts) apart
// from the last operation: a later enable / backup must not hide a failed
// hostname change that SetHosts re-applies.
func (h *Hub) hostsOpPath(id string) string { return filepath.Join(h.opsDir(), id+".hosts.json") }

// loadOps reads the stored records (unreadable ones are skipped).
func (h *Hub) loadOps() {
	h.ops = map[string]OpRecord{}
	h.hostsOps = map[string]OpRecord{}
	entries, _ := os.ReadDir(h.opsDir())
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), ".hosts.json"); ok && templates.ValidID(id) {
			var r OpRecord
			if data, err := os.ReadFile(filepath.Join(h.opsDir(), e.Name())); err == nil && json.Unmarshal(data, &r) == nil {
				h.hostsOps[id] = r
			}
			continue
		}
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !validOpKey(id) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(h.opsDir(), e.Name()))
		if err != nil {
			continue
		}
		var r OpRecord
		if json.Unmarshal(data, &r) != nil {
			continue
		}
		if r.Running {
			// The Hub stopped while it ran: it never finished. Restores
			// are recovered by RecoverRestores, deletes stay "deleting".
			r.Running, r.OK, r.Status = false, false, 500
			r.Error = "interrupted: the Hub stopped while this " + r.Op + " was running — check the instance and run it again"
			if out, err := json.MarshalIndent(r, "", "  "); err == nil {
				if err := fsutil.WriteFileAtomic(filepath.Join(h.opsDir(), e.Name()), out, 0600); err != nil {
					log.Printf("ops: cannot mark %s %s interrupted: %v", r.Op, id, err)
				}
			}
			log.Printf("ops: %s %s was interrupted by a Hub stop", r.Op, id)
		}
		h.ops[id] = r
	}
}

// validOpKey: an op record key loadOps keeps — an instance id, a shared
// folder's opKeyFolder ("_folder.<id>") or the doctor's ("_doctor",
// ruling 20).
func validOpKey(k string) bool {
	if fid, ok := strings.CutPrefix(k, "_folder."); ok {
		return settings.FolderIDRe.MatchString(fid)
	}
	return k == opKeyDoctor || templates.ValidID(k)
}

// LastOp returns an app's last recorded operation (nil: none).
func (h *Hub) LastOp(id string) *OpRecord {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	if r, ok := h.ops[id]; ok {
		return &r
	}
	return nil
}

// lastHostsOp is id's last hostname change record (nil: none).
func (h *Hub) lastHostsOp(id string) *OpRecord {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	if r, ok := h.hostsOps[id]; ok {
		return &r
	}
	return nil
}

// FailedOps maps app ID → operation, for apps whose last operation failed.
func (h *Hub) FailedOps() map[string]string {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	out := map[string]string{}
	for id, r := range h.ops {
		// Folder and doctor records (_folder.<id>, _doctor) are no app.
		if strings.HasPrefix(id, "_") {
			continue
		}
		if !r.OK && !r.Running {
			out[id] = r.Op
		}
	}
	return out
}

// finishOp records the outcome of op on id and returns err as an
// *OpError carrying compose's (redacted) output and a hint, or nil.
// Unknown apps and busy refusals are not recorded.
func (h *Hub) finishOp(id, op string, err error, rolledBack bool) error {
	return h.finishOpGuarded(id, op, err, rolledBack, false)
}

// finishDeliveryOp records a settings delivery's outcome (op reload, hook) as
// finishOp does, except over another operation's running record, which a
// delivery never replaces (P20).
func (h *Hub) finishDeliveryOp(id, op string, err error) {
	h.finishOpGuarded(id, op, err, false, true)
}

// finishOpGuarded is finishOp; keepRunning: leave a running record in place.
func (h *Hub) finishOpGuarded(id, op string, err error, rolledBack, keepRunning bool) error {
	var busy ErrBusy
	if errors.As(err, &busy) || errors.Is(err, ErrNotFound) || !templates.ValidID(id) {
		return err
	}
	if h.Template(id) == nil && !h.IsEnabled(id) {
		return err // e.g. "template not found": nothing to show it on
	}
	r := h.opRecordOf(id, op, err, rolledBack)
	h.opsMu.Lock()
	if cur := h.ops[id]; keepRunning && cur.Running {
		h.opsMu.Unlock()
		log.Printf("ops: %s %s not recorded: %s is running (%s)", op, id, cur.Op, r.Error)
		if err == nil {
			return nil
		}
		return &OpError{Record: r, Err: err}
	}
	// The operation's compose up succeeded and its start hook failed
	// after it: the hook's failure stays the instance's record (only
	// that one: a hostname change's own record is still written).
	keepHook := err == nil && op != OpHook && h.startHookFailed[id]
	delete(h.startHookFailed, id)
	if !keepHook {
		h.ops[id] = r
	}
	if op == OpHosts {
		h.hostsOps[id] = r
	}
	// The files under opsMu too: memory and disk never disagree with
	// another writer's record (recordOp).
	if data, merr := json.MarshalIndent(r, "", "  "); merr == nil {
		if !keepHook {
			if werr := fsutil.WriteFileAtomic(h.opPath(id), data, 0600); werr != nil {
				log.Printf("ops: cannot record %s %s: %v", op, id, werr)
			}
		}
		if op == OpHosts {
			if werr := fsutil.WriteFileAtomic(h.hostsOpPath(id), data, 0600); werr != nil {
				log.Printf("ops: cannot record %s %s: %v", op, id, werr)
			}
		}
	}
	h.opsMu.Unlock()
	if keepHook {
		log.Printf("ops: %s %s succeeded; its start hook's failure stays recorded", op, id)
	}
	if err == nil {
		return nil
	}
	log.Printf("%s %s failed: %s", op, id, r.Error)
	return &OpError{Record: r, Err: err}
}

// opRecordOf is op's record for err on id (nil = ok): the redacted, then
// clipped error, compose's (redacted) output and a hint.
func (h *Hub) opRecordOf(id, op string, err error, rolledBack bool) OpRecord {
	r := OpRecord{Op: op, At: time.Now().UTC(), OK: err == nil, RolledBack: rolledBack}
	if err != nil {
		redact := h.secretRedactor(id, secretsOf(err))
		// Redact, then clip (never the other way round: a cut secret's
		// prefix would escape redaction).
		r.Error = clipRunes(redact(err.Error()), 600)
		var ce *compose.Error
		if errors.As(err, &ce) {
			r.Output = redact(ce.Output)
		}
		r.Hint = opHint(r.Error + "\n" + r.Output)
	}
	return r
}

var bindInUseRe = regexp.MustCompile(`(?i)(?:bind(?: host port)?(?: for)? |listen \w+ )((?:\[[0-9a-fA-F:.]*\]|[0-9.]*):\d+(?:/(?:tcp|udp))?)`)

// opHint turns well-known compose failures into an actionable hint.
func opHint(out string) string {
	low := strings.ToLower(out)
	if strings.Contains(low, "address already in use") || strings.Contains(low, "port is already allocated") {
		port := "A host port"
		if m := bindInUseRe.FindStringSubmatch(out); m != nil {
			port = "Host port " + m[1]
		}
		return port + " this app publishes is already in use on the server, by a service outside Portcullis " +
			"(e.g. systemd-resolved holds port 53) or another container. Open the app's Settings → Host Ports to " +
			"change the host port, bind it to a specific address, or leave it empty to disable the binding — then try again."
	}
	return ""
}

var secretKeyRe = regexp.MustCompile(`(?i)secret|passw|token|key|salt|credential|private|auth|cookie`)

// secretRedactor returns a function that blanks, in s, the instance's
// redaction set (redactionSet: stored secret settings, whatever their
// length, and the values of the app's and core's secret-looking env
// variables and generated ones) plus extra — the values an operation
// captured when it started (an archive's secrets, the store before a
// delete), which may be gone from the instance when it finishes. Compose
// doesn't print env values on up/down, but its error output is shown to
// the browser and stored: never let one through. Used by finishOp, the
// async ops (finishAsync) and auditOp; redact, then clip.
func (h *Hub) secretRedactor(id string, extra ...[]string) func(string) string {
	vals, err := h.redactionSetErr(id)
	if err != nil {
		// F44, fail closed: a person_secret instance whose hashes can't be
		// read shows no text that could hold one — only why.
		msg := "the message is hidden: " + id + "'s secrets couldn't be read to redact it (" + err.Error() + ")"
		return func(string) string { return msg }
	}
	for _, x := range extra {
		vals = append(vals, x...)
	}
	return func(s string) string { return redactValues(s, vals) }
}

// redactionSets is the union of ids' redaction sets (redactionSetErr);
// err names the first instance whose set couldn't be read whole — the
// caller hides its messages then (hideIfUnread).
func (h *Hub) redactionSets(ids ...string) ([]string, error) {
	var out []string
	var first error
	for _, id := range ids {
		vals, err := h.redactionSetErr(id)
		if err != nil && first == nil {
			first = fmt.Errorf("%s: %w", id, err)
		}
		out = append(out, vals...)
	}
	return out, first
}

// hiddenErr is an error whose text is never shown: the secrets it might
// hold couldn't be read to redact it (fail closed). Unwrap keeps its
// status and the values it carries.
type hiddenErr struct{ err, why error }

func (e *hiddenErr) Error() string {
	return "the message is hidden: secrets couldn't be read to redact it (" + e.why.Error() + ")"
}
func (e *hiddenErr) Unwrap() error { return e.err }

// hideIfUnread is err with its message hidden when why (a redaction set
// read error) is set; nil stays nil.
func hideIfUnread(err, why error) error {
	if err == nil || why == nil {
		return err
	}
	return &hiddenErr{err: err, why: why}
}

// redactOrHide is s redacted with vals, or the hidden text when why is set.
func redactOrHide(s string, vals []string, why error) string {
	if why != nil {
		return (&hiddenErr{why: why}).Error()
	}
	return redactValues(s, vals)
}

// redactionSetErr is redactionSet plus the instance's current NT hashes
// (upper and lower case, F44) and every model provider secret (G30(c));
// err: they exist but can't be read.
func (h *Hub) redactionSetErr(id string) ([]string, error) {
	t := h.Template(id)
	var vals []string
	for _, p := range []string{h.envPath(id), filepath.Join(h.cfg.ProjectDir, ".env")} {
		vals = append(vals, envSecrets(t, readEnvFile(p))...)
	}
	vals = append(vals, h.knownSecrets(id)...)
	// G30(c): every model provider secret, whichever instance selects it.
	ps, perr := h.providerSecretValues()
	vals = append(vals, ps...)
	hs, err := h.credentialHashes(id, t)
	return append(vals, hs...), errors.Join(err, perr)
}

// envSecrets are the values in vars (an env file, unquoted) that look
// secret: generated by t's manifest (t may be nil) or named like a secret,
// 6 characters or more.
func envSecrets(t *templates.Template, vars map[string]string) []string {
	generated := map[string]bool{}
	if t != nil {
		for _, e := range t.Manifest.Env {
			if e.Generate != "" && e.Generate != "none" {
				generated[e.Key] = true
			}
		}
	}
	var vals []string
	for k, v := range vars {
		if len(v) >= 6 && (generated[k] || secretKeyRe.MatchString(k)) {
			vals = append(vals, v)
		}
	}
	return vals
}

// secretsErr is an error carrying the values its operation must redact
// (secretRedactor's extra): its text is already redacted with them, and
// finishOp, finishAsync and auditOp pick them up (secretsOf).
type secretsErr struct {
	err   error
	extra []string
}

func (e *secretsErr) Error() string { return redactValues(e.err.Error(), e.extra) }
func (e *secretsErr) Unwrap() error { return e.err }

// withSecrets wraps err (nil stays nil) with values to redact.
func withSecrets(err error, extra []string) error {
	if err == nil || len(extra) == 0 {
		return err
	}
	return &secretsErr{err: err, extra: extra}
}

// secretsOf are the values err carries for redaction (withSecrets).
func secretsOf(err error) []string {
	var out []string
	switch e := err.(type) {
	case nil:
		return nil
	case *secretsErr:
		out = append(out, e.extra...)
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		out = append(out, secretsOf(u.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, x := range u.Unwrap() {
			out = append(out, secretsOf(x)...)
		}
	}
	return out
}

// clipRunes shortens s to at most n bytes on a rune boundary.
func clipRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
