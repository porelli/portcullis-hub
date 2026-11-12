package hub

// The FIDO metadata the Keycloak extension classifies passkeys against
// (contract §8.1 "FIDO metadata (Hub)", plan D15): RunMDS loads the
// cached BLOB, refreshes it daily and whenever its nextUpdate has passed,
// and republishes signin-keycloak.json; every publish derives the trust
// list again (fidomds.Trust: a stale BLOB publishes none) and, with
// HUB_DEV=1 only, merges HUB_SIGNIN_EXTRA_AUTHENTICATORS over it.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/fidomds"
)

// MDSCacheFile is the cached BLOB under the data directory.
const MDSCacheFile = "signin/mds.jwt"

// mdsStaleWarning is Settings → Sign-in's warning while the FIDO list is
// stale.
const mdsStaleWarning = "The FIDO list is out of date: new passkeys count as synced until it refreshes"

// mdsRetry is the wait after a failed refresh (at most the period).
const mdsRetry = time.Hour

// mdsState is the FIDO list the Hub publishes from (its own leaf lock,
// never held across mu or I/O).
type mdsState struct {
	mu      sync.Mutex
	fetcher *fidomds.Fetcher   // nil = no fetching (no HUB_FIDO_MDS_URL)
	meta    *metadata.Metadata // the last good BLOB (nil = none yet)
	// models: AAGUID → model name of meta (fidomds.Models; display only),
	// read-only, replaced as a whole by setMDS.
	models map[string]string
	status fidomds.Status
	// extraMtime / extraGen: the extra-authenticators file's last mtime
	// seen and how many distinct ones (HUB_DEV: added to mds.serial so
	// touching the file makes the extension reclassify). Under
	// policyWriteMu too (only writePolicy reads the file).
	extraMtime int64
	extraGen   int
	// staleLogged: the stale BLOB has been logged once.
	staleLogged bool
	// badRootsLogged: AAGUIDs whose entry was left out (or, revoked,
	// published without some roots) for a root that isn't DER X.509 or no
	// roots, each logged once (publishableTrust).
	badRootsLogged map[string]bool
	// The development serial (extra file on, signInDevSerial): the last
	// published serial (read once from signin-keycloak.json), and the
	// BLOB serial and generation it was published for.
	pubLoaded       bool
	pubSerial       int
	lastNo, lastGen int
	// now is the clock (nil = time.Now; tests set it before RunMDS).
	now func() time.Time
	// hwFile: the last failure was the unreadable high-water serial file
	// (its path; "" = another cause or none).
	hwFile string
	// floor: production's second floor (the serial signin-keycloak.json
	// had published at RunMDS's start); never published below either.
	floor int
}

func (h *Hub) mdsNow() time.Time {
	if h.mds.now != nil {
		return h.mds.now()
	}
	return time.Now()
}

func newMDSFetcher(cfg Config) *fidomds.Fetcher {
	if cfg.FIDOMDSURL == "" {
		return nil
	}
	return &fidomds.Fetcher{URL: cfg.FIDOMDSURL, CacheFile: filepath.Join(cfg.DataDir, filepath.FromSlash(MDSCacheFile))}
}

// mdsModels is the last good BLOB's AAGUID → model name map (nil: none
// yet). Read-only: setMDS replaces it whole, never edits it.
func (h *Hub) mdsModels() map[string]string {
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	return h.mds.models
}

// SetMDSModelsForTest sets the AAGUID → model names the Sign-in page
// shows (tests and the harness only: no FIDO list there). Panics outside
// tests.
func (h *Hub) SetMDSModelsForTest(models map[string]string) {
	if !testing.Testing() {
		panic("SetMDSModelsForTest: refuses to work outside tests")
	}
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	h.mds.models = models
}

// setMDS records a good BLOB m and its status.
func (h *Hub) setMDS(m *metadata.Metadata, st *fidomds.Status) {
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	if m != nil {
		h.mds.meta = m
		h.mds.models = fidomds.Models(m)
		h.mds.hwFile = ""
	}
	if st != nil {
		h.mds.status = *st
	}
}

// setMDSFailure records a failed load or refresh (st the kept BLOB's
// status, nil = none): Err set, and whether the high-water serial's file
// was the cause.
func (h *Hub) setMDSFailure(st *fidomds.Status, err error, f *fidomds.Fetcher) {
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	if st != nil {
		h.mds.status = *st
	}
	h.mds.status.Err = err.Error()
	h.mds.hwFile = ""
	if errors.Is(err, fidomds.ErrHighWater) {
		h.mds.hwFile = f.HighWaterFile()
	}
}

// mdsProblem is the FIDO list's unavailability (no BLOB loaded and the
// last load or refresh failed; nil = none): the doctor's
// signin_fido_list_unavailable and Settings → Sign-in's warning.
func (h *Hub) mdsProblem() *doctor.SignInMDSIn {
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	if h.mds.meta != nil || h.mds.status.Err == "" {
		return nil
	}
	return &doctor.SignInMDSIn{Err: h.mds.status.Err, HighWaterFile: h.mds.hwFile}
}

// mdsWarning is Settings → Sign-in's FIDO list warning ("" = none): the
// list is unavailable (naming the high-water file when it is the cause)
// or stale.
func (h *Hub) mdsWarning(st fidomds.Status) string {
	if p := h.mdsProblem(); p != nil {
		w := "The FIDO list isn't available (" + p.Err + "): new passkeys count as synced until it loads."
		if p.HighWaterFile != "" {
			w += " Fix " + p.HighWaterFile + " (it holds the highest FIDO list serial accepted): the Hub refuses every FIDO list until it can read it."
		}
		return w
	}
	if st.Stale {
		return mdsStaleWarning
	}
	return ""
}

// mdsStatus is the FIDO list's status now (Stale computed for now).
func (h *Hub) mdsStatus() fidomds.Status {
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	st := h.mds.status
	st.Stale = h.mds.meta != nil && fidomds.IsStale(st.NextUpdate, h.mdsNow())
	return st
}

// signInTrust is signin-keycloak.json's authenticators and mds: the MDS
// trust list now (empty while stale or before a good BLOB) and the BLOB's
// serial; in development only (Config.Dev and Config.ExtraAuthenticators,
// both checked here too) the extra-authenticators file's entries merged
// over it (a file that doesn't read or decode adds nothing, logged) and
// the development serial (signInDevSerial). Reads files: never under mu.
// Every certified entry with a root that isn't one DER X.509 certificate
// is left out; a revoked one is published without such roots
// (publishableTrust). Caller holds policyWriteMu.
func (h *Hub) signInTrust() (map[string]fidomds.AuthenticatorTrust, KeycloakMDS) {
	trust, doc := h.signInTrustAll()
	kept, dropped := publishableTrust(trust)
	h.mds.mu.Lock()
	if h.mds.badRootsLogged == nil {
		h.mds.badRootsLogged = map[string]bool{}
	}
	for _, d := range dropped {
		if !h.mds.badRootsLogged[d.aaguid] {
			h.mds.badRootsLogged[d.aaguid] = true
			if d.revoked {
				log.Printf("signin: revoked authenticator %s published in signin-keycloak.json without its unusable roots: %s", d.aaguid, d.why)
			} else {
				log.Printf("signin: authenticator %s left out of signin-keycloak.json: %s (its passkeys register as synced)", d.aaguid, d.why)
			}
		}
	}
	h.mds.mu.Unlock()
	return kept, doc
}

// droppedTrust is an entry publishableTrust left out (revoked false), or
// a revoked entry it published without some roots (revoked true), and why.
type droppedTrust struct {
	aaguid, why string
	revoked     bool
}

// publishableTrust keeps the entries the Keycloak extension can read
// (contract §8.1 "FIDO metadata (Hub)"). A certified entry needs at least
// one root, each exactly one DER X.509 certificate: the extension refuses
// the whole file for a certified entry without roots (every sign-in
// denied), so a bad one is dropped instead — its model then counts as the
// weaker, synced kind. A revoked entry is always published, with only its
// usable roots (`roots: []` when none is: the extension accepts empty
// roots only for revoked), so the revocation still downgrades that model.
// dropped is sorted by AAGUID.
func publishableTrust(trust map[string]fidomds.AuthenticatorTrust) (map[string]fidomds.AuthenticatorTrust, []droppedTrust) {
	kept := make(map[string]fidomds.AuthenticatorTrust, len(trust))
	var dropped []droppedTrust
	der := func(r []byte) bool {
		c, err := x509.ParseCertificate(r)
		return err == nil && bytes.Equal(c.Raw, r)
	}
	for id, t := range trust {
		if t.Status == fidomds.StatusRevoked {
			roots := make([][]byte, 0, len(t.Roots))
			var bad []string
			for i, r := range t.Roots {
				if der(r) {
					roots = append(roots, r)
				} else {
					bad = append(bad, strconv.Itoa(i+1))
				}
			}
			if len(bad) > 0 {
				dropped = append(dropped, droppedTrust{id, fmt.Sprintf("root %s isn't a DER X.509 certificate", strings.Join(bad, ", ")), true})
			}
			t.Roots = roots
			kept[id] = t
			continue
		}
		why := ""
		if len(t.Roots) == 0 {
			why = "no attestation roots"
		}
		for i, r := range t.Roots {
			if !der(r) {
				why = fmt.Sprintf("root %d isn't a DER X.509 certificate", i+1)
				break
			}
		}
		if why != "" {
			dropped = append(dropped, droppedTrust{id, why, false})
			continue
		}
		kept[id] = t
	}
	slices.SortFunc(dropped, func(a, b droppedTrust) int { return strings.Compare(a.aaguid, b.aaguid) })
	return kept, dropped
}

// signInTrustAll is signInTrust before publishableTrust.
func (h *Hub) signInTrustAll() (map[string]fidomds.AuthenticatorTrust, KeycloakMDS) {
	h.mds.mu.Lock()
	trust, stale := fidomds.Trust(h.mds.meta, h.mdsNow())
	if stale && !h.mds.staleLogged {
		log.Printf("signin: the FIDO list (BLOB %d) is more than 30 days past its next update: no authenticators published until it refreshes", h.mds.status.Serial)
	}
	h.mds.staleLogged = stale
	// Never below the floor: a refused older BLOB (or none yet) must not
	// lower the published serial the next start floors on.
	doc := KeycloakMDS{Serial: max(h.mds.status.Serial, h.mds.floor), NextUpdate: h.mds.status.NextUpdate.UTC()}
	h.mds.mu.Unlock()

	path := h.cfg.ExtraAuthenticators
	if path == "" || !h.cfg.Dev {
		return trust, doc
	}
	extra, mtime, err := readExtraAuthenticators(path)
	var last int
	loadLast := false
	h.mds.mu.Lock()
	loadLast = !h.mds.pubLoaded
	h.mds.mu.Unlock()
	if loadLast {
		last = lastPublishedSerial(h.signInKeycloakPath())
	}
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	if loadLast && !h.mds.pubLoaded {
		h.mds.pubLoaded, h.mds.pubSerial, h.mds.lastNo, h.mds.lastGen = true, last, -1, -1
	}
	if err == nil && mtime != h.mds.extraMtime {
		h.mds.extraMtime = mtime
		h.mds.extraGen++
	}
	doc.Serial = h.signInDevSerialLocked(doc.Serial)
	if err != nil {
		log.Printf("signin: HUB_SIGNIN_EXTRA_AUTHENTICATORS %s refused, no extra authenticators: %v", path, err)
		return trust, doc
	}
	maps.Copy(trust, extra)
	return trust, doc
}

// signInDevSerialLocked is the development mds.serial for BLOB serial no:
// no + the extra file's generation, never below the last published one
// (across restarts: signin-keycloak.json's), and above it whenever no or
// the generation changed (the extension reclassifies only when it grows).
// Caller holds mds.mu.
func (h *Hub) signInDevSerialLocked(no int) int {
	gen := h.mds.extraGen
	s := max(no+gen, h.mds.pubSerial)
	if no != h.mds.lastNo || gen != h.mds.lastGen {
		s = max(no+gen, h.mds.pubSerial+1)
	}
	h.mds.pubSerial, h.mds.lastNo, h.mds.lastGen = s, no, gen
	return s
}

// lastPublishedSerial is mds.serial of the signin-keycloak.json at path
// (0 when there is none or it doesn't read).
func lastPublishedSerial(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var doc struct {
		MDS struct {
			Serial int `json:"serial"`
		} `json:"mds"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.MDS.Serial < 0 {
		return 0
	}
	return doc.MDS.Serial
}

var aaguidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// readExtraAuthenticators reads HUB_SIGNIN_EXTRA_AUTHENTICATORS (HUB_DEV
// only): `{"<aaguid>": {"kind", "status", "roots": [base64 DER]}}`,
// strictly — lowercase hyphenated AAGUIDs, each once; kind security_key
// or passkey_device; status certified or revoked; at least one root, each
// a certificate; no unknown field, missing field or trailing data. Also
// the file's mtime (UnixNano).
func readExtraAuthenticators(path string) (map[string]fidomds.AuthenticatorTrust, int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, 0, errors.New("not a JSON object")
	}
	out := map[string]fidomds.AuthenticatorTrust{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		aaguid, _ := tok.(string)
		if !aaguidRe.MatchString(aaguid) {
			return nil, 0, fmt.Errorf("%q is not a lowercase hyphenated AAGUID", aaguid)
		}
		if _, dup := out[aaguid]; dup {
			return nil, 0, fmt.Errorf("%s is listed twice", aaguid)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, 0, err
		}
		var e struct {
			Kind   *string   `json:"kind"`
			Status *string   `json:"status"`
			Roots  *[][]byte `json:"roots"`
		}
		ed := json.NewDecoder(bytes.NewReader(raw))
		ed.DisallowUnknownFields()
		if err := ed.Decode(&e); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", aaguid, err)
		}
		switch {
		case e.Kind == nil || e.Status == nil || e.Roots == nil:
			return nil, 0, fmt.Errorf("%s: kind, status and roots are required", aaguid)
		case *e.Kind != fidomds.KindSecurityKey && *e.Kind != fidomds.KindPasskeyDevice:
			return nil, 0, fmt.Errorf("%s: kind %q is not security_key or passkey_device", aaguid, *e.Kind)
		case *e.Status != fidomds.StatusCertified && *e.Status != fidomds.StatusRevoked:
			return nil, 0, fmt.Errorf("%s: status %q is not certified or revoked", aaguid, *e.Status)
		case len(*e.Roots) == 0:
			return nil, 0, fmt.Errorf("%s: no roots", aaguid)
		}
		for i, r := range *e.Roots {
			if _, err := x509.ParseCertificate(r); err != nil {
				return nil, 0, fmt.Errorf("%s: root %d: %w", aaguid, i, err)
			}
		}
		out[aaguid] = fidomds.AuthenticatorTrust{Kind: *e.Kind, Status: *e.Status, Roots: *e.Roots}
	}
	if _, err := dec.Token(); err != nil {
		return nil, 0, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, errors.New("trailing data after the object")
	}
	return out, fi.ModTime().UnixNano(), nil
}

// RunMDS keeps the FIDO list current until ctx ends: the cached BLOB
// first (published at once), then a refresh when none is cached, the
// cache is `every` old or its nextUpdate has passed; then every `every`
// (sooner at nextUpdate), mdsRetry after a failure. A good refresh
// republishes signin-keycloak.json; a failed one keeps the last good
// BLOB (fidomds never caches a BLOB that doesn't verify). Fetching runs
// outside mu.
func (h *Hub) RunMDS(ctx context.Context, every time.Duration) {
	f := h.mds.fetcher
	if f == nil {
		log.Printf("signin: no FIDO metadata URL: passkeys register as synced")
		return
	}
	if every <= 0 {
		every = 24 * time.Hour
	}
	if !h.cfg.Dev {
		// The second floor (production: the published serial is the
		// BLOB's no): no BLOB below what signin-keycloak.json published.
		f.Floor = lastPublishedSerial(h.signInKeycloakPath())
		h.mds.mu.Lock()
		h.mds.floor = f.Floor
		h.mds.mu.Unlock()
	}
	m, st, err := f.Load()
	if err == nil {
		h.setMDS(m, st)
		h.writePolicyLogged()
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("signin: FIDO metadata cache: %v", err)
		h.setMDSFailure(nil, err, f)
	}
	wait := time.Duration(0)
	if err == nil {
		wait = h.mdsWait(*st, every)
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := f.Refresh(ctx)
		if ctx.Err() != nil {
			return // shutting down: no republish
		}
		if err != nil {
			log.Printf("signin: FIDO metadata refresh failed (keeping BLOB %d): %v", st.Serial, err)
			h.setMDSFailure(st, err, f)
			// Republish: the kept BLOB may have gone stale meanwhile
			// (it then publishes no authenticators).
			h.writePolicyLogged()
			t.Reset(capStale(min(every, mdsRetry), *st, h.mdsNow()))
			continue
		}
		m, st2, err := f.Load()
		if err != nil {
			log.Printf("signin: FIDO metadata: %v", err)
			h.setMDSFailure(nil, err, f)
			h.writePolicyLogged()
			t.Reset(min(every, mdsRetry))
			continue
		}
		h.setMDS(m, st2)
		log.Printf("signin: FIDO metadata BLOB %d (next update %s)", st2.Serial, st2.NextUpdate.Format(time.DateOnly))
		h.writePolicyLogged()
		t.Reset(h.mdsWait(*st2, every))
	}
}

// mdsWait is RunMDS's next wait: mdsNextWait, but never past the moment
// the BLOB goes stale (capStale: a run then, even a failing one,
// republishes the empty list).
func (h *Hub) mdsWait(st fidomds.Status, every time.Duration) time.Duration {
	now := h.mdsNow()
	return capStale(mdsNextWait(st, every, now), st, now)
}

// capStale caps wait at the moment st's BLOB goes stale (just past
// nextUpdate + fidomds.StaleAfter), when that is still ahead.
func capStale(wait time.Duration, st fidomds.Status, now time.Time) time.Duration {
	if st.NextUpdate.IsZero() {
		return wait
	}
	staleAt := st.NextUpdate.Add(fidomds.StaleAfter + time.Second)
	if d := staleAt.Sub(now); d > 0 && d < wait {
		return d
	}
	return wait
}

// mdsNextWait is when to refresh next: `every` after the fetch, sooner
// at nextUpdate; once nextUpdate has passed (FIDO is late), mdsRetry
// after the fetch; 0 when that is already due.
func mdsNextWait(st fidomds.Status, every time.Duration, now time.Time) time.Duration {
	due := st.FetchedAt.Add(every)
	switch {
	case st.NextUpdate.IsZero():
	case st.NextUpdate.After(now):
		due = minTime(due, st.NextUpdate)
	default:
		due = minTime(due, st.FetchedAt.Add(mdsRetry))
	}
	return max(due.Sub(now), 0)
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
