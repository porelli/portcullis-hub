package hub

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The per-person credential store (contract §6, §11.6, §13.16): one
// <secrets>/<instance>/<key>/<user>.nt per active credential on the
// hub_secrets volume (HUB_SECRETS_DIR; directories 0700, files 0600,
// owned by the Hub), their metadata in state.yaml (Credentials, never a
// hash), and the secrets epoch in both (SecretsEpoch, <secrets>/.epoch).
// Everything here runs under h.mu (local file I/O only).

// DefaultSecretsVolume is core's hub_secrets volume (HUB_SECRETS_VOLUME).
const DefaultSecretsVolume = "portcullis_hub_secrets"

// epochFile is the secrets epoch's copy on the volume.
const epochFile = ".epoch"

// secretNameRe: what a username or option key may be in a secrets path
// (F46), whatever the template's username rule says. Instance ids too.
var secretNameRe = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,63}$`)

// ntHashRe: a hash file's content (uppercase hex MD4, §13.16).
var ntHashRe = regexp.MustCompile(`^[0-9A-F]{32}$`)

// checkSecretsDir is why dir can't hold the hashes ("" = it can): an
// absolute directory (not a symlink), owned by the Hub's uid, mode 0700
// exactly (F14). New records the answer; the credential routes answer
// 503 and person_secret instances refuse to enable or start with it.
func checkSecretsDir(dir string) error {
	if dir == "" {
		return errors.New("HUB_SECRETS_DIR is not set")
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("HUB_SECRETS_DIR %q must be a clean absolute path", clip(dir, 200))
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%s: %v", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0700 {
		return fmt.Errorf("%s has mode %04o: it must be 0700", dir, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: can't read its owner", dir)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d: it must be owned by the Hub's uid %d", dir, st.Uid, os.Getuid())
	}
	return nil
}

// SecretsUsable is nil when the secrets volume can hold credentials,
// else a 503 naming why (checked once, in New). The credential routes
// answer it; person_secret instances refuse to enable or start with it.
//
// A failed reconcile (fix round 1) makes it 503 too, until a later
// reconcile succeeds: this call retries it (under mu), so the next
// credential route or start after the cause is fixed reconciles first.
func (h *Hub) SecretsUsable() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.secretsUsableLocked(true)
}

// secretsBaseErr is the 503 for an unusable volume (New's check).
func (h *Hub) secretsBaseErr() error {
	if h.secretsErr != nil {
		return statusErr(http.StatusServiceUnavailable, "the Hub's secrets volume is not usable (%v): per-person passwords are unavailable", h.secretsErr)
	}
	return nil
}

// secretsUsableLocked is SecretsUsable under mu (write); retry reconciles
// again first while the last reconcile failed.
func (h *Hub) secretsUsableLocked(retry bool) error {
	if err := h.secretsBaseErr(); err != nil {
		return err
	}
	if h.secretsReconcileErr != nil && retry {
		h.retryReconcileLocked()
	}
	if h.secretsReconcileErr != nil {
		return statusErr(http.StatusServiceUnavailable, "the Hub's secrets volume could not be reconciled (%v): per-person passwords are unavailable until it is", h.secretsReconcileErr)
	}
	return nil
}

// retryReconcileLocked runs the reconcile again (after a failed one),
// advancing the pools on a mismatch as reconcileSecrets does. Caller
// must hold mu (write).
func (h *Hub) retryReconcileLocked() {
	_, mismatch, err := h.reconcileSecretsLocked("retry")
	if err != nil {
		log.Printf("secrets: reconcile retry: %v", err)
		return
	}
	if mismatch && !h.poolsAdvanced {
		before := h.snapshotPoolsLocked()
		h.advancePoolsLocked(PoolRewindStep)
		if err := h.commitPoolsLocked(true, before); err != nil {
			log.Printf("ERROR: secrets: advancing the person-id pools after an epoch mismatch failed: %v", err)
			return
		}
		h.poolsAdvanced = true
	}
}

// secretRel is the hash file of (instance, key, user) relative to
// SecretsDir. Names outside secretNameRe are refused (500, logged; F46).
func secretRel(instance, key, user string) (string, error) {
	for _, n := range []struct{ what, v string }{{"instance", instance}, {"option key", key}, {"username", user}} {
		if !secretNameRe.MatchString(n.v) {
			log.Printf("ERROR: secrets: refusing the %s %q in a secrets path", n.what, clip(n.v, 80))
			return "", statusErr(http.StatusInternalServerError, "the %s %q can't be used in a secrets path", n.what, clip(n.v, 80))
		}
	}
	return path.Join(instance, key, user+".nt"), nil
}

// secretDirRel is <instance>/<key> (the names checked as in secretRel).
func secretDirRel(instance, key string) (string, error) {
	rel, err := secretRel(instance, key, "x")
	if err != nil {
		return "", err
	}
	return path.Dir(rel), nil
}

// secretPath is the hash file of (instance, key, user) under SecretsDir
// (refused like secretRel; confined under SecretsDir).
func (h *Hub) secretPath(instance, key, user string) (string, error) {
	rel, err := secretRel(instance, key, user)
	if err != nil {
		return "", err
	}
	p := filepath.Join(h.cfg.SecretsDir, filepath.FromSlash(rel))
	if h.cfg.SecretsDir == "" || !fsutil.Within(h.cfg.SecretsDir, p) || p == h.cfg.SecretsDir {
		log.Printf("ERROR: secrets: %q is outside %s", p, h.cfg.SecretsDir)
		return "", statusErr(http.StatusInternalServerError, "a secrets path is outside the secrets volume")
	}
	return p, nil
}

// openSecrets opens SecretsDir as an os.Root: every access stays inside
// it (no "..", no symlink out).
func (h *Hub) openSecrets() (*os.Root, error) {
	if err := h.secretsBaseErr(); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(h.cfg.SecretsDir)
	if err != nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the Hub's secrets volume can't be opened: %v", err)
	}
	return r, nil
}

// writeRootAtomic writes name in r (temp file, fsync, rename; 0600).
func writeRootAtomic(r *os.Root, name string, data []byte) error {
	var rnd [6]byte
	rand.Read(rnd[:])
	tmp := name + ".tmp-" + hex.EncodeToString(rnd[:])
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer r.Remove(tmp) // no-op after the rename
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return r.Rename(tmp, name)
}

// mkdirSecrets makes rel (and its parents) 0700 directories in r, never
// through a symlink.
func mkdirSecrets(r *os.Root, rel string) error {
	if err := r.MkdirAll(rel, 0700); err != nil {
		return err
	}
	cur := ""
	for _, seg := range strings.Split(rel, "/") {
		cur = path.Join(cur, seg)
		fi, err := r.Lstat(cur)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", cur)
		}
		if fi.Mode().Perm() != 0700 {
			if err := r.Chmod(cur, 0700); err != nil {
				return err
			}
		}
	}
	return nil
}

// newEpoch is a fresh secrets epoch: 16 random bytes, hex.
func newEpoch() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// readEpoch is <secrets>/.epoch ("" = missing or unreadable).
func readEpoch(r *os.Root) string {
	b, err := r.ReadFile(epochFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// rotateEpochLocked writes a new secrets epoch: the volume's .epoch
// first, then state.yaml (which persists the caller's metadata changes
// with it). A failed volume write changes nothing (500). A failed
// state.yaml save keeps the in-memory epoch equal to the volume's and
// answers 500: the copy on disk differs, so the next start voids every
// credential (F57, fail closed). Caller must hold mu (write).
func (h *Hub) rotateEpochLocked(r *os.Root) error {
	ep := newEpoch()
	if err := writeRootAtomic(r, epochFile, []byte(ep)); err != nil {
		log.Printf("ERROR: secrets: writing the epoch failed: %v", err)
		return statusErr(http.StatusInternalServerError, "the secrets epoch could not be written (%v): nothing was saved", err)
	}
	h.st.SecretsEpoch = ep
	if err := h.st.Save(h.statePath()); err != nil {
		log.Printf("ERROR: secrets: saving state.yaml after an epoch rotation failed: %v — every per-person password is voided at the next start", err)
		return statusErr(http.StatusInternalServerError, "saving the Hub's state failed (%v): every per-person password will be reset at the next start", err)
	}
	return nil
}

// writeHashLocked writes (instance, key, user)'s hash file (hash: 32
// uppercase hex) and rotates the epoch (volume, then state.yaml). The
// caller sets the credential's metadata in h.st first (the rotation's
// save persists it) and undoes it on an error; the hash file then
// written, if any, has no active metadata and goes at the next
// reconcile. Caller must hold mu (write).
func (h *Hub) writeHashLocked(instance, key, user, hash string) error {
	rel, err := secretRel(instance, key, user)
	if err != nil {
		return err
	}
	if !ntHashRe.MatchString(hash) {
		// Never echoed: it may be a secret in the wrong form.
		return statusErr(http.StatusInternalServerError, "refusing to write a hash file that isn't an NT hash")
	}
	if err := h.secretsUsableLocked(false); err != nil {
		return err
	}
	r, err := h.openSecrets()
	if err != nil {
		return err
	}
	defer r.Close()
	if err := mkdirSecrets(r, path.Dir(rel)); err != nil {
		return statusErr(http.StatusInternalServerError, "the secrets directory of %s/%s: %v", instance, key, err)
	}
	if err := writeRootAtomic(r, rel, []byte(hash+"\n")); err != nil {
		return statusErr(http.StatusInternalServerError, "writing the hash file of %s on %s/%s failed: %v", user, instance, key, err)
	}
	return h.rotateEpochLocked(r)
}

// removeHashLocked removes (instance, key, user)'s hash file (missing is
// fine) and rotates the epoch. The caller updates the metadata first,
// as for writeHashLocked. Caller must hold mu (write).
func (h *Hub) removeHashLocked(instance, key, user string) error {
	rel, err := secretRel(instance, key, user)
	if err != nil {
		return err
	}
	r, err := h.openSecrets()
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return statusErr(http.StatusInternalServerError, "removing the hash file of %s on %s/%s failed: %v", user, instance, key, err)
	}
	return h.rotateEpochLocked(r)
}

// voidActiveLocked marks every active credential of instance voided
// (reason, at now) and returns how many. Caller must hold mu (write).
func (h *Hub) voidActiveLocked(instance, reason string, now time.Time) int {
	n := 0
	for _, users := range h.st.Credentials[instance] {
		for u, c := range users {
			if !c.Active() {
				continue
			}
			at := now
			c.RevokedAt, c.RevokedBy, c.Reason = &at, "", reason
			users[u] = c
			n++
		}
	}
	return n
}

// cloneCredentials deep-copies one instance's credential metadata.
func cloneCredentials(in map[string]map[string]state.Credential) map[string]map[string]state.Credential {
	if in == nil {
		return nil
	}
	out := make(map[string]map[string]state.Credential, len(in))
	for k, users := range in {
		m := make(map[string]state.Credential, len(users))
		for u, c := range users {
			m[u] = c
		}
		out[k] = m
	}
	return out
}

// voidCredentialsLocked voids every credential of instance (a restore,
// §11.6): its hash files go, each active credential is marked voided
// with reason, the epoch rotates, and credential.void_restore is
// audited once with the count when it is above 0. Nothing to void is
// no change. Caller must hold mu (write).
func (h *Hub) voidCredentialsLocked(instance, reason string) (int, error) {
	if _, err := secretDirRel(instance, "x"); err != nil {
		return 0, err
	}
	active := 0
	for _, users := range h.st.Credentials[instance] {
		for _, c := range users {
			if c.Active() {
				active++
			}
		}
	}
	if err := h.secretsBaseErr(); err != nil {
		if active == 0 {
			return 0, nil // nothing to void; no file can be checked
		}
		return 0, err
	}
	r, err := h.openSecrets()
	if err != nil {
		return 0, err
	}
	defer r.Close()
	_, statErr := r.Lstat(instance)
	if active == 0 && errors.Is(statErr, fs.ErrNotExist) {
		return 0, nil
	}
	n := h.voidActiveLocked(instance, reason, time.Now().UTC())
	if rmErr := r.RemoveAll(instance); rmErr != nil {
		// Fail closed: the metadata is voided (saved with the epoch), and
		// until a reconcile removes the leftover files no person_secret
		// instance starts (fix round 1).
		h.secretsReconcileErr = fmt.Errorf("removing the hash files of %s failed: %v", instance, rmErr)
		log.Printf("ERROR: secrets: %v — per-person password apps won't start until it is fixed", h.secretsReconcileErr)
		rerr := h.rotateEpochLocked(r)
		h.auditVoidLocked(instance, n)
		return n, errors.Join(statusErr(http.StatusInternalServerError, "removing the hash files of %s failed: %v", instance, rmErr), rerr)
	}
	err = h.rotateEpochLocked(r)
	h.auditVoidLocked(instance, n)
	return n, err
}

// forgetCredentialsLocked removes instance's hash files (<secrets>/<id>/)
// and its credential metadata (a delete, §11.4 step 3; no per-credential
// audit) and rotates the epoch. Caller must hold mu (write).
func (h *Hub) forgetCredentialsLocked(instance string) error {
	if _, err := secretDirRel(instance, "x"); err != nil {
		return err
	}
	_, hasMeta := h.st.Credentials[instance]
	if err := h.secretsBaseErr(); err != nil {
		if !hasMeta {
			log.Printf("secrets: %s: the secrets volume is not usable, no hash file of the instance can be left (none recorded)", instance)
			return nil
		}
		return err
	}
	r, err := h.openSecrets()
	if err != nil {
		return err
	}
	defer r.Close()
	_, statErr := r.Lstat(instance)
	if !hasMeta && errors.Is(statErr, fs.ErrNotExist) {
		return nil
	}
	if err := r.RemoveAll(instance); err != nil {
		return statusErr(http.StatusInternalServerError, "removing the hash files of %s failed: %v", instance, err)
	}
	delete(h.st.Credentials, instance)
	return h.rotateEpochLocked(r)
}

// auditVoidLocked audits credential.void_restore count=n for instance
// (n > 0 only). The audit log is a local file: allowed under mu.
func (h *Hub) auditVoidLocked(instance string, n int) {
	if n <= 0 {
		return
	}
	log.Printf("secrets: %s: %d per-person password(s) voided (reset by a restore)", instance, n)
	if h.audit == nil {
		return
	}
	e := directory.AuditEntry{Actor: purgeActor, Action: "credential.void_restore", Target: instance, Detail: fmt.Sprintf("count=%d reason=%s", n, state.CredentialReasonRestore), Result: "ok"}
	if err := h.audit.Append(e); err != nil {
		log.Printf("audit: %v", err)
	}
}

// reconcileSecrets compares the secrets epoch in state.yaml with the
// volume's (at boot and before every credentials delivery, §11.6).
// Missing or different: every credential of every instance is voided
// (reason restore, audited per instance), the volume emptied, a new
// epoch written to both, and every person-id pool advanced by
// PoolRewindStep (once per process) before any allocation. Then hash
// files without active metadata are deleted and active metadata without
// a hash file is voided. why names the caller in the log. Takes mu.
func (h *Hub) reconcileSecrets(why string) (voided int, err error) {
	h.mu.Lock()
	voided, mismatch, err := h.reconcileSecretsLocked(why)
	h.mu.Unlock()
	if mismatch {
		h.initStage("pools")
		if perr := h.AdvancePools(PoolRewindStep); perr != nil {
			log.Printf("ERROR: secrets: advancing the person-id pools after an epoch mismatch failed: %v", perr)
			err = errors.Join(err, perr)
		}
	}
	return voided, err
}

func (h *Hub) reconcileSecretsLocked(why string) (voided int, mismatch bool, err error) {
	// Any failure fails closed until a reconcile succeeds (fix round 1):
	// the voids may be in memory only and old hash files still there.
	defer func() {
		h.secretsReconcileErr = err
		if err != nil {
			log.Printf("ERROR: secrets: %s: reconcile failed: %v — per-person password apps won't start until it succeeds", why, err)
		}
	}()
	r, err := h.openSecrets()
	if err != nil {
		return 0, false, err
	}
	defer r.Close()
	now := time.Now().UTC()
	counts := map[string]int{}
	changed := false
	disk := readEpoch(r)
	if disk == "" || disk != h.st.SecretsEpoch {
		mismatch, changed = true, true
		log.Printf("secrets: %s: the secrets epoch of state.yaml and the volume differ (a core restore, a new volume or an interrupted change): every per-person password is voided", why)
		for inst := range h.st.Credentials {
			counts[inst] += h.voidActiveLocked(inst, state.CredentialReasonRestore, now)
		}
		entries, err := fs.ReadDir(r.FS(), ".")
		if err != nil {
			return 0, true, statusErr(http.StatusInternalServerError, "reading the secrets volume: %v", err)
		}
		for _, e := range entries {
			if err := r.RemoveAll(e.Name()); err != nil {
				return 0, true, statusErr(http.StatusInternalServerError, "emptying the secrets volume: %v", err)
			}
		}
	} else {
		c, n, err := h.reconcileOrphansLocked(r, now)
		if err != nil {
			return 0, false, err
		}
		changed = c
		for inst, k := range n {
			counts[inst] += k
		}
	}
	if changed {
		err = h.rotateEpochLocked(r)
	}
	insts := make([]string, 0, len(counts))
	for inst := range counts {
		insts = append(insts, inst)
	}
	sort.Strings(insts)
	for _, inst := range insts {
		voided += counts[inst]
		h.auditVoidLocked(inst, counts[inst])
	}
	return voided, mismatch, err
}

// reconcileOrphansLocked deletes every file on the volume that isn't
// the epoch or the hash file of an active credential (leftover temp
// files, revoked or unknown people, unknown names) and voids active
// metadata without a hash file. Returns whether anything changed and
// the voids per instance. Caller must hold mu (write).
func (h *Hub) reconcileOrphansLocked(r *os.Root, now time.Time) (bool, map[string]int, error) {
	changed := false
	remove := func(name string) error {
		changed = true
		log.Printf("secrets: removing %s from the secrets volume (no active credential)", name)
		if err := r.RemoveAll(name); err != nil {
			return statusErr(http.StatusInternalServerError, "removing %s from the secrets volume: %v", name, err)
		}
		return nil
	}
	present := map[string]bool{} // "inst/key/user"
	top, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		return false, nil, statusErr(http.StatusInternalServerError, "reading the secrets volume: %v", err)
	}
	for _, ie := range top {
		inst := ie.Name()
		if inst == epochFile && ie.Type().IsRegular() {
			continue
		}
		if !ie.IsDir() || !secretNameRe.MatchString(inst) {
			if err := remove(inst); err != nil {
				return false, nil, err
			}
			continue
		}
		keys, err := fs.ReadDir(r.FS(), inst)
		if err != nil {
			return false, nil, statusErr(http.StatusInternalServerError, "reading the secrets volume: %v", err)
		}
		for _, ke := range keys {
			key := ke.Name()
			kdir := inst + "/" + key
			if !ke.IsDir() || !secretNameRe.MatchString(key) {
				if err := remove(kdir); err != nil {
					return false, nil, err
				}
				continue
			}
			files, err := fs.ReadDir(r.FS(), kdir)
			if err != nil {
				return false, nil, statusErr(http.StatusInternalServerError, "reading the secrets volume: %v", err)
			}
			for _, fe := range files {
				name := fe.Name()
				user, isNT := strings.CutSuffix(name, ".nt")
				c, ok := h.st.Credentials[inst][key][user]
				if isNT && fe.Type().IsRegular() && secretNameRe.MatchString(user) && ok && c.Active() {
					present[inst+"/"+key+"/"+user] = true
					continue
				}
				if err := remove(kdir + "/" + name); err != nil {
					return false, nil, err
				}
			}
		}
	}
	counts := map[string]int{}
	for inst, keys := range h.st.Credentials {
		for key, users := range keys {
			for u, c := range users {
				if !c.Active() || present[inst+"/"+key+"/"+u] {
					continue
				}
				at := now
				c.RevokedAt, c.RevokedBy, c.Reason = &at, "", state.CredentialReasonRestore
				users[u] = c
				counts[inst]++
				changed = true
			}
		}
	}
	return changed, counts, nil
}

// personSecretOptions are t's person_secret options (with a mount).
func personSecretOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].Type == templates.TypePersonSecret && opts[i].Mount != nil {
			out = append(out, &opts[i])
		}
	}
	return out
}

// ensureSecretDirsLocked makes <secrets>/<id>/<key>/ (0700) for each of
// t's person_secret options before an up (the subpath mount needs it;
// Docker would refuse a missing subpath). An unusable secrets volume
// refuses the start (503, F14). Caller must hold mu.
func (h *Hub) ensureSecretDirsLocked(t *templates.Template) error {
	opts := personSecretOptions(t)
	if len(opts) == 0 {
		return nil
	}
	if err := h.secretsUsableLocked(true); err != nil {
		return statusErr(http.StatusServiceUnavailable, "%s has per-person passwords, but %v: it is not started", t.ID, err)
	}
	r, err := h.openSecrets()
	if err != nil {
		return err
	}
	defer r.Close()
	for _, o := range opts {
		rel, err := secretDirRel(t.ID, o.Key)
		if err != nil {
			return err
		}
		if err := mkdirSecrets(r, rel); err != nil {
			return statusErr(http.StatusInternalServerError, "the secrets directory of %s/%s: %v", t.ID, o.Key, err)
		}
	}
	return nil
}
