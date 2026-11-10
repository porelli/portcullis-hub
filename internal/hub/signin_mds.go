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
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"

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
	status  fidomds.Status
	// extraMtime / extraGen: the extra-authenticators file's last mtime
	// seen and how many distinct ones (HUB_DEV: added to mds.serial so
	// touching the file makes the extension reclassify). Under
	// policyWriteMu too (only writePolicy reads the file).
	extraMtime int64
	extraGen   int
	// staleLogged: the stale BLOB has been logged once.
	staleLogged bool
	// The development serial (extra file on, signInDevSerial): the last
	// published serial (read once from signin-keycloak.json), and the
	// BLOB serial and generation it was published for.
	pubLoaded       bool
	pubSerial       int
	lastNo, lastGen int
	// now is the clock (nil = time.Now; tests set it before RunMDS).
	now func() time.Time
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

// setMDS records a good BLOB m and its status.
func (h *Hub) setMDS(m *metadata.Metadata, st *fidomds.Status) {
	h.mds.mu.Lock()
	defer h.mds.mu.Unlock()
	if m != nil {
		h.mds.meta = m
	}
	if st != nil {
		h.mds.status = *st
	}
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
// Caller holds policyWriteMu.
func (h *Hub) signInTrust() (map[string]fidomds.AuthenticatorTrust, KeycloakMDS) {
	h.mds.mu.Lock()
	trust, stale := fidomds.Trust(h.mds.meta, h.mdsNow())
	if stale && !h.mds.staleLogged {
		log.Printf("signin: the FIDO list (BLOB %d) is more than 30 days past its next update: no authenticators published until it refreshes", h.mds.status.Serial)
	}
	h.mds.staleLogged = stale
	doc := KeycloakMDS{Serial: h.mds.status.Serial, NextUpdate: h.mds.status.NextUpdate.UTC()}
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
	m, st, err := f.Load()
	if err == nil {
		h.setMDS(m, st)
		h.writePolicyLogged()
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
		if err != nil {
			log.Printf("signin: FIDO metadata refresh failed (keeping BLOB %d): %v", st.Serial, err)
			h.setMDS(nil, st)
			// Republish: the kept BLOB may have gone stale meanwhile
			// (it then publishes no authenticators).
			h.writePolicyLogged()
			t.Reset(capStale(min(every, mdsRetry), *st, h.mdsNow()))
			continue
		}
		m, st2, err := f.Load()
		if err != nil {
			log.Printf("signin: FIDO metadata: %v", err)
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
