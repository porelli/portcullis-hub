package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	// OpAI: a per-instance AI support change (ai_instance.go, §15.11).
	OpAI = "ai"
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
	// Progress (progress.go, contract §11.7 "The op record"): the
	// operation's steps in order, what it created (written as it
	// happens), and its Stop state. StoppedBy / StoppedAt: who pressed
	// Stop and when (the user only). Interrupted: the Hub stopped while
	// it ran (loadOps).
	Steps           []Step     `json:"steps,omitempty"`
	Created         *Created   `json:"created,omitempty"`
	Stopping        bool       `json:"stopping,omitempty"`
	Stoppable       bool       `json:"stoppable,omitempty"`
	PointOfNoReturn bool       `json:"point_of_no_return,omitempty"`
	StoppedBy       string     `json:"stopped_by,omitempty"`
	StoppedAt       *time.Time `json:"stopped_at,omitempty"`
	Interrupted     bool       `json:"interrupted,omitempty"`
	// Before: what a Stop puts back, written before the operation changes
	// anything (Progress.Before), so a Stop of an interrupted record undoes
	// from it: a restart's "running" (true / false), an AI switch's
	// "companion:<name>" ("on <mode>" / "off <mode>").
	Before map[string]string `json:"before,omitempty"`
}

// Stopped: the operation ended because a Stop was accepted and its undo
// finished (contract §11.7 "Stopped": ok false, no error). A stopped
// operation is no failure.
func (r OpRecord) Stopped() bool {
	return !r.Running && !r.OK && r.StoppedAt != nil && r.Error == ""
}

// Failed: the operation ended and failed — not running, not ok and not
// stopped (FailedOps, the instance's state "error").
func (r OpRecord) Failed() bool { return !r.OK && !r.Running && !r.Stopped() }

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

// opHistoryKept is how many ended records the op history keeps per
// instance (contract §11.7 "Op history"): the oldest goes when the 21st is
// written.
const opHistoryKept = 20

// OpIDRe is an operation id (newOpID: 16 lowercase hex digits).
var OpIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// opHistoryDir holds id's ended records by op id (<id>.d/<op_id>.json).
func (h *Hub) opHistoryDir(id string) string { return filepath.Join(h.opsDir(), id+".d") }

// keepHistoryLocked keeps r, an ended record with an op id of instance
// id, in the op history and prunes it to opHistoryKept (the caller holds
// opsMu). Running records, records without an op id (finishOp's: hook,
// hosts, reload, credentials, drift) and non-instance keys (_folder.<id>,
// _doctor) are never kept.
func (h *Hub) keepHistoryLocked(id string, r OpRecord) {
	if r.Running || !OpIDRe.MatchString(r.OpID) || !templates.ValidID(id) {
		return
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return
	}
	dir := h.opHistoryDir(id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("ops: cannot keep %s %s (%s): %v", r.Op, id, r.OpID, err)
		return
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, r.OpID+".json"), data, 0600); err != nil {
		log.Printf("ops: cannot keep %s %s (%s): %v", r.Op, id, r.OpID, err)
		return
	}
	h.pruneHistory(dir)
}

// pruneHistory removes the oldest kept records (by at, the end; then by
// name) beyond opHistoryKept.
func (h *Hub) pruneHistory(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type kept struct {
		name string
		at   time.Time
	}
	var all []kept
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !OpIDRe.MatchString(id) || !e.Type().IsRegular() {
			continue
		}
		all = append(all, kept{name: e.Name()})
	}
	if len(all) <= opHistoryKept {
		return
	}
	for i := range all {
		var r OpRecord
		if data, err := os.ReadFile(filepath.Join(dir, all[i].name)); err == nil && json.Unmarshal(data, &r) == nil {
			all[i].at = r.At
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].at.Equal(all[j].at) {
			return all[i].at.After(all[j].at)
		}
		return all[i].name > all[j].name
	})
	for _, k := range all[opHistoryKept:] {
		if err := os.Remove(filepath.Join(dir, k.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("ops: cannot prune %s: %v", filepath.Join(dir, k.name), err)
		}
	}
}

// OpByID is instance id's record of operation opID (contract §11.7 "Op
// history"): the current record when it is that operation's, the running
// operation's when it is the one asked for, else its kept final record;
// nil when the instance has none (unknown, or pruned).
func (h *Hub) OpByID(id, opID string) *OpRecord {
	if !OpIDRe.MatchString(opID) || !templates.ValidID(id) {
		return nil
	}
	h.opsMu.Lock()
	if r, ok := h.ops[id]; ok && r.OpID == opID {
		h.opsMu.Unlock()
		return &r
	}
	h.opsMu.Unlock()
	h.opRunsMu.Lock()
	run := h.opRuns[id]
	h.opRunsMu.Unlock()
	if run != nil && run.opID == opID {
		if r, ok := run.p.liveRecord(); ok {
			return &r
		}
	}
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	if r, ok := h.ops[id]; ok && r.OpID == opID {
		return &r // it ended meanwhile and is still the instance's
	}
	data, err := os.ReadFile(filepath.Join(h.opHistoryDir(id), opID+".json"))
	if err != nil {
		return nil
	}
	var r OpRecord
	if json.Unmarshal(data, &r) != nil || r.OpID != opID {
		return nil
	}
	return &r
}

// OpSummary is an instance's current record in short (GET
// /api/instances/ops: the UI's card states).
type OpSummary struct {
	Op        string    `json:"op"`
	OpID      string    `json:"op_id"`
	Running   bool      `json:"running"`
	Stopping  bool      `json:"stopping"`
	Stoppable bool      `json:"stoppable"`
	OK        bool      `json:"ok"`
	At        time.Time `json:"at"`
}

// OpSummaries maps every instance id with a record (deleted instances'
// included; no _folder / _doctor key) to its current record in short.
func (h *Hub) OpSummaries() map[string]OpSummary {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	out := make(map[string]OpSummary, len(h.ops))
	for id, r := range h.ops {
		if !templates.ValidID(id) {
			continue
		}
		out[id] = OpSummary{Op: r.Op, OpID: r.OpID, Running: r.Running, Stopping: r.Stopping, Stoppable: r.Stoppable, OK: r.OK, At: r.At}
	}
	return out
}

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
			markInterrupted(&r)
			if out, err := json.MarshalIndent(r, "", "  "); err == nil {
				if err := fsutil.WriteFileAtomic(filepath.Join(h.opsDir(), e.Name()), out, 0600); err != nil {
					log.Printf("ops: cannot mark %s %s interrupted: %v", r.Op, id, err)
				}
			}
			// Its kept record says interrupted too (?op_id= answers it
			// once a newer operation replaced the instance's record).
			h.keepHistoryLocked(id, r)
			log.Printf("ops: %s %s was interrupted by a Hub stop", r.Op, id)
		}
		h.ops[id] = r
	}
}

// markInterrupted rewrites a record still running at load (contract
// §11.7 "Shutdown and interruption"): running false, interrupted, ok
// false, status 500; the running step is stopped, the other steps and
// created stay as last written. It is stoppable (a Stop undoes from the
// record) only when it has steps to undo from, and never for the three
// cases recovered at start: a restore (same instance: rolled back;
// into a new id: removed, both RecoverRestores) and any operation past
// its point of no return (a delete stays "deleting").
func markInterrupted(r *OpRecord) {
	// Its Stop gate was closed (CloseStop wrote stoppable false while it
	// ran, not stopping): it committed, nothing is undone any more.
	committed := r.Running && !r.Stoppable && !r.Stopping
	r.Running, r.OK, r.Status, r.Interrupted, r.Stopping = false, false, 500, true, false
	r.Error = "interrupted: the Hub stopped while this " + r.Op + " was running — check the instance and run it again"
	for i := range r.Steps {
		if r.Steps[i].State == StepRunning {
			r.Steps[i].State = StepStopped
		}
	}
	r.Stoppable = len(r.Steps) > 0 && r.Op != OpRestore && !r.PointOfNoReturn && !committed
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
		if r.Failed() {
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
		// A hook's outcome under a running operation's record is held
		// and written once that operation ended ok (heldHook,
		// finishAsync): a failed start hook still becomes the instance's
		// record, as startHookFailed keeps it for a synchronous one.
		if op == OpHook {
			if err != nil {
				if h.heldHook == nil {
					h.heldHook = map[string]heldHookRec{}
				}
				h.heldHook[id] = heldHookRec{opID: cur.OpID, rec: r}
			} else if h.heldHook[id].opID == cur.OpID {
				delete(h.heldHook, id)
			}
		}
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

// prefixOpError is err (nil stays nil) with prefix before its text, as
// operation op's own outcome: an *OpError inside err (a backup's failed
// start-again, the pre-backup of a delete or restore) becomes op's record
// with prefix before its error — output, hint and rolled_back kept —,
// so finishAsync's errors.As finds this one, never the inner record
// without the prefix. The chain (statuses, secretsOf) is err's.
func prefixOpError(op, prefix string, err error) error {
	if err == nil {
		return nil
	}
	wrapped := fmt.Errorf("%s%w", prefix, err)
	var oe *OpError
	if !errors.As(err, &oe) {
		return wrapped
	}
	rec := oe.Record
	rec.Op, rec.At = op, time.Now().UTC() // op's own end (the history orders by it)
	rec.Error = clipRunes(prefix+oe.Record.Error, 600)
	return &OpError{Record: rec, Err: wrapped}
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
// secret, 6 characters or more: a variable SecretEnvNames lists (t may be
// nil), or one named like a secret that isn't a Hub-set public instance
// variable.
func envSecrets(t *templates.Template, vars map[string]string) []string {
	secretNames := SecretEnvNames(t)
	var vals []string
	for k, v := range vars {
		if len(v) >= 6 && (secretNames[k] || (secretKeyRe.MatchString(k) && !HubPublicVar(k))) {
			vals = append(vals, v)
		}
	}
	return vals
}

// SecretEnvNames are the env variables of t (nil: none) that always hold
// a secret, whatever their name: every Keycloak client's secret_env,
// every secret option's env names and every generated env entry (Task
// 17b fix round 1, security review). HubPublicVar never applies to them.
func SecretEnvNames(t *templates.Template) map[string]bool {
	out := map[string]bool{}
	if t == nil {
		return out
	}
	for _, c := range t.Manifest.Clients {
		if c.SecretEnv != "" {
			out[c.SecretEnv] = true
		}
	}
	for _, e := range t.Manifest.Env {
		if e.Generate != "" && e.Generate != "none" {
			out[e.Key] = true
		}
	}
	for n := range secretOptionEnvNames(t) {
		out[n] = true
	}
	return out
}

// SecretOptionEnvNames are t's secret options' env names (their values
// are write-only: Env shows them as [set]).
func SecretOptionEnvNames(t *templates.Template) map[string]bool {
	if t == nil {
		return map[string]bool{}
	}
	return secretOptionEnvNames(t)
}

// hubPublicVars / hubPublicPrefixes are the instance variables the Hub
// writes into every instance's .env (contract §3.1) whose values are
// never secrets: hostnames, ids, group names, client ids, the local
// networks, the AI switches and COMPOSE_PROFILES (the setup choices'
// compose profiles, §13.18). Templates may not declare them (reserved
// names), so a name matching secretKeyRe here (PORTCULLIS_HOST_SECRETAPP,
// PORTCULLIS_INSTANCE of an id with "token" in it) is still not a
// secret's variable. PORTCULLIS_AI_PROVIDER_* are secrets and stay out.
var (
	hubPublicVars = map[string]bool{
		"PORTCULLIS_DOMAIN": true, "PORTCULLIS_INSTANCE": true, "PORTCULLIS_OIDC_CLIENT_ID": true,
		"PORTCULLIS_ACCESS_GROUP": true, "PORTCULLIS_ADMIN_GROUP": true, "PORTCULLIS_LOCAL_NETWORKS": true,
		"PORTCULLIS_AI_ENABLED": true, templates.VarComposeProfiles: true,
	}
	hubPublicPrefixes = []string{"PORTCULLIS_HOST_", "PORTCULLIS_OIDC_CLIENT_ID_", "PORTCULLIS_AI_READONLY_"}
)

// HubPublicVar: name is a Hub-set instance variable whose value is no
// secret (hubPublicVars): never redacted for its name (Task 17b fix
// round 1 — the global tool redactor blanked hostnames of instances
// whose id looks secret).
// Callers check SecretEnvNames first: a template's secret variable is
// never public (its names can't be reserved ones anyway).
func HubPublicVar(name string) bool {
	if hubPublicVars[name] {
		return true
	}
	for _, p := range hubPublicPrefixes {
		if strings.HasPrefix(name, p) && len(name) > len(p) {
			return true
		}
	}
	return false
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

// SecretLookingEnvName: name looks like a secret's variable (the rule
// envSecrets redacts values by) — the Portcullis MCP's save_env refuses
// writing one (secrets never pass through the AI).
func SecretLookingEnvName(name string) bool { return secretKeyRe.MatchString(name) }
