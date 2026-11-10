package fidomds

// Fetching, verifying and caching the FIDO Alliance Metadata Service BLOB
// (contract §8.1 "FIDO metadata (Hub)", plan D15). go-webauthn's metadata
// decoder verifies the JWS: its x5c chain to the trust anchor (the FIDO
// production root unless Fetcher.Roots says otherwise), the chain
// certificates' revocation and the signature. Never fail open: a BLOB that
// doesn't verify, is older than the cached one or already stale is never
// cached, and a failed fetch keeps the last good BLOB.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/x/revoke"

	"github.com/portcullis/hub/internal/fsutil"
)

// DefaultURL is the FIDO Alliance MDS3 endpoint (HUB_FIDO_MDS_URL's
// default).
const DefaultURL = "https://mds3.fidoalliance.org/"

// StaleAfter is how long past its nextUpdate a BLOB is still used; after
// that it publishes no authenticators.
const StaleAfter = 30 * 24 * time.Hour

// maxBlobBytes bounds a fetched BLOB (the production one is a few MB).
const maxBlobBytes = 64 << 20

func init() {
	// The decoder checks the chain's revocation (CRL / OCSP) through this
	// package-level client, http.DefaultClient (no timeout) unless set:
	// never let it hang the MDS loop. Set once, before any use.
	revoke.HTTPClient = &http.Client{Timeout: 30 * time.Second}
}

// Status is the cached BLOB's serial ("no"), nextUpdate and when it was
// fetched (the cache file's time), whether it is stale (more than
// StaleAfter past nextUpdate) and the last refresh error ("" = none).
// Zero before the first good BLOB.
type Status struct {
	Serial     int       `json:"serial"`
	NextUpdate time.Time `json:"next_update"`
	FetchedAt  time.Time `json:"fetched_at"`
	Stale      bool      `json:"stale"`
	Err        string    `json:"error,omitempty"`
}

// Fetcher fetches the BLOB from URL, verifies it against Roots (nil = the
// FIDO production root) and caches it at CacheFile (0600 in a 0700
// directory). HTTP nil = a client with a 60 s timeout; Now nil = time.Now.
type Fetcher struct {
	URL       string
	CacheFile string
	Roots     *x509.CertPool
	HTTP      *http.Client
	Now       func() time.Time

	mu   sync.Mutex
	meta *metadata.Metadata // the last good BLOB, parsed (nil = not loaded)
	st   Status
}

func (f *Fetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Fetcher) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// IsStale: now is more than StaleAfter past next.
func IsStale(next, now time.Time) bool { return now.After(next.Add(StaleAfter)) }

// Load is the last good BLOB: from memory, else read from the cache file
// and verified again (a cache that doesn't verify is an error, never
// trusted). Status.Stale is computed for Now. No cache = an error and a
// zero Status.
func (f *Fetcher) Load() (*metadata.Metadata, *Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	st := f.statusLocked()
	return m, &st, err
}

func (f *Fetcher) loadLocked() (*metadata.Metadata, error) {
	if f.meta != nil {
		return f.meta, nil
	}
	raw, err := os.ReadFile(f.CacheFile)
	if err != nil {
		return nil, fmt.Errorf("fido mds: no cached BLOB: %w", err)
	}
	m, err := f.decode(raw)
	if err != nil {
		return nil, fmt.Errorf("fido mds: cached BLOB refused: %w", err)
	}
	var at time.Time
	if fi, err := os.Stat(f.CacheFile); err == nil {
		at = fi.ModTime().UTC()
	}
	f.meta = m
	f.st = Status{Serial: m.Parsed.Number, NextUpdate: m.Parsed.NextUpdate, FetchedAt: at}
	return m, nil
}

func (f *Fetcher) statusLocked() Status {
	st := f.st
	st.Stale = f.meta != nil && IsStale(st.NextUpdate, f.now())
	return st
}

// Refresh fetches, verifies and caches the BLOB. On any failure (fetch,
// verification, a serial lower than the cached one, a BLOB already
// stale, the cache write) the cache is kept and the Status is the cached
// one with Err set. Runs the network fetch outside the Fetcher's lock.
func (f *Fetcher) Refresh(ctx context.Context) (*Status, error) {
	raw, err := f.fetch(ctx)
	var m *metadata.Metadata
	if err == nil {
		m, err = f.decode(raw)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	prev, _ := f.loadLocked() // the cached BLOB, if any (for the serial check)
	if err == nil {
		switch {
		case IsStale(m.Parsed.NextUpdate, f.now()):
			err = fmt.Errorf("fido mds: BLOB %d is expired (next update %s)", m.Parsed.Number, m.Parsed.NextUpdate.Format(time.DateOnly))
		case prev != nil && m.Parsed.Number < prev.Parsed.Number:
			err = fmt.Errorf("fido mds: BLOB %d is older than the cached %d", m.Parsed.Number, prev.Parsed.Number)
		default:
			err = f.writeCache(raw)
		}
	}
	if err != nil {
		f.st.Err = err.Error()
		st := f.statusLocked()
		return &st, err
	}
	f.meta = m
	f.st = Status{Serial: m.Parsed.Number, NextUpdate: m.Parsed.NextUpdate, FetchedAt: f.now().UTC()}
	st := f.statusLocked()
	return &st, nil
}

func (f *Fetcher) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("fido mds: %w", err)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fido mds: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fido mds: fetch: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBlobBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fido mds: fetch: %w", err)
	}
	if len(b) > maxBlobBytes {
		return nil, errors.New("fido mds: fetch: BLOB too large")
	}
	return b, nil
}

// writeCache stores raw at CacheFile: the directory 0700 (tightened when
// it exists), the file 0600, atomically. The file's time is FetchedAt.
func (f *Fetcher) writeCache(raw []byte) error {
	dir := filepath.Dir(f.CacheFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("fido mds: cache: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("fido mds: cache: %w", err)
	}
	if err := fsutil.WriteFileAtomic(f.CacheFile, raw, 0600); err != nil {
		return fmt.Errorf("fido mds: cache: %w", err)
	}
	t := f.now()
	_ = os.Chtimes(f.CacheFile, t, t)
	return nil
}

// decode verifies raw and parses it (entries that don't parse are left
// out: an unknown model counts as the weaker kind).
func (f *Fetcher) decode(raw []byte) (*metadata.Metadata, error) {
	opts := []metadata.DecoderOption{metadata.WithIgnoreEntryParsingErrors()}
	if f.Roots != nil {
		root, err := anchorIn(raw, f.Roots)
		if err != nil {
			return nil, err
		}
		opts = append(opts, metadata.WithRootCertificate(base64.StdEncoding.EncodeToString(root.Raw)))
	}
	d, err := metadata.NewDecoder(opts...)
	if err != nil {
		return nil, err
	}
	p, err := d.DecodeBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("fido mds: BLOB doesn't verify: %w", err)
	}
	return d.Parse(p)
}

// anchorIn is the certificate of pool that raw's x5c chain verifies to:
// the decoder takes one trust anchor and checks the chain (and the
// signature) again against it.
func anchorIn(raw []byte, pool *x509.CertPool) (*x509.Certificate, error) {
	hdr, _, ok := strings.Cut(string(raw), ".")
	if !ok {
		return nil, errors.New("fido mds: not a JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(hdr)
	if err != nil {
		return nil, errors.New("fido mds: bad JWS header")
	}
	var h struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(hb, &h); err != nil || len(h.X5C) < 2 {
		return nil, errors.New("fido mds: the BLOB has no x5c chain")
	}
	var chain []*x509.Certificate
	for _, s := range h.X5C {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("fido mds: bad x5c certificate")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("fido mds: bad x5c certificate: %w", err)
		}
		chain = append(chain, c)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	chains, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, fmt.Errorf("fido mds: BLOB doesn't verify: %w", err)
	}
	c := chains[0]
	return c[len(c)-1], nil
}
