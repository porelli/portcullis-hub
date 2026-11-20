// Package publish is how the Hub hands a document to the services that
// read it (contract §4 "On Kubernetes: published documents", §8.1,
// §20.5): the policy file, user-attributes.json, portal-apps.json,
// signin-keycloak.json, impersonation.json, the two mcp-gate files and
// vpn.json. On Docker and Podman a FileSink writes today's files, byte
// for byte; on Kubernetes the kube backend's DocSink updates one named
// ConfigMap (or the Secret) per document and confirms that every reader
// pod mounts the new revision.
package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Doc is a published document: its key without ".json"
// (published_docs.json "doc").
type Doc string

// The eight documents (contract §4's table).
const (
	GroupGatePolicy Doc = "group-gate-policy"
	UserAttributes  Doc = "user-attributes"
	PortalApps      Doc = "portal-apps"
	SignInKeycloak  Doc = "signin-keycloak"
	Impersonation   Doc = "impersonation"
	MCPGate         Doc = "mcp-gate"
	MCPCredentials  Doc = "mcp-credentials"
	VPN             Doc = "vpn"
)

// All lists every Doc in published_docs.json's order.
var All = []Doc{GroupGatePolicy, UserAttributes, PortalApps, SignInKeycloak, Impersonation, MCPGate, MCPCredentials, VPN}

// MaxDoc is the largest document published (the object limit with room
// for .rev): a larger one is never published, truncated or emptied.
const MaxDoc = 1_000_000

// ErrTooLarge: the document is over MaxDoc; the last good one stays.
var ErrTooLarge = errors.New("the document is over 1 000 000 bytes: not published, the last good one stays")

// ErrEmpty: an empty document is never published.
var ErrEmpty = errors.New("an empty document is never published")

// Kind is the object kind a document is published as.
type Kind string

const (
	ConfigMap Kind = "configmap"
	Secret    Kind = "secret"
)

// DocSpec is one row of published_docs.json.
type DocSpec struct {
	Object  string
	Kind    Kind
	Key     string
	Mount   string
	Readers []string
	// Mode is the projected mode; FSGroup the reader pod's fsGroup the
	// Secret is readable through (0: none, the ConfigMaps).
	Mode    string
	FSGroup int
	// Optional: the reader projects the items optional: true (an absent
	// key, as created or withdrawn, is a missing file; contract §4).
	Optional bool
	doc      Doc
}

// RevKey is the item path the object's .rev projects to.
func (s DocSpec) RevKey() string { return ".rev-" + string(s.doc) }

// RevPath is where a reader sees the revision.
func (s DocSpec) RevPath() string { return s.Mount + "/" + s.RevKey() }

func cm(d Doc, mount string, readers ...string) DocSpec {
	return DocSpec{Object: "pub-" + string(d), Kind: ConfigMap, Key: string(d) + ".json", Mount: mount, Readers: readers, Mode: "0444", Optional: true, doc: d}
}

var specs = map[Doc]DocSpec{
	GroupGatePolicy: cm(GroupGatePolicy, "/hub-data", "group-gate"),
	UserAttributes:  cm(UserAttributes, "/hub-data", "group-gate"),
	PortalApps:      cm(PortalApps, "/hub-data", "group-gate"),
	SignInKeycloak:  cm(SignInKeycloak, "/hub-data", "keycloak"),
	Impersonation:   cm(Impersonation, "/hub-data", "group-gate", "keycloak"),
	MCPGate:         cm(MCPGate, "/hub-data", "mcp-gate"),
	MCPCredentials: {Object: "pub-mcp-credentials", Kind: Secret, Key: "mcp-credentials.json", Mount: "/hub-data", Readers: []string{"mcp-gate"},
		Mode: "0440", FSGroup: 10001, Optional: true, doc: MCPCredentials},
	VPN: cm(VPN, "/vpn-doc", "group-gate", "wg"),
}

// Spec is d's row (the zero DocSpec for an unknown d).
func Spec(d Doc) DocSpec { return specs[d] }

// Known: d is one of All.
func Known(d Doc) bool { _, ok := specs[d]; return ok }

// Rev is a document's revision: the first 16 hex digits of the sha256
// of its bytes (the object's .rev).
func Rev(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])[:16]
}

// Check refuses what is never published: an unknown document, an empty
// one, and (max > 0) one over max bytes. Kubernetes publishes at most
// MaxDoc; the files of Docker and Podman have no limit (unchanged).
func Check(d Doc, data []byte, max int) error {
	switch {
	case !Known(d):
		return fmt.Errorf("publish: unknown document %q", d)
	case len(data) == 0:
		return fmt.Errorf("%s: %w", d, ErrEmpty)
	case max > 0 && len(data) > max:
		return fmt.Errorf("%s (%d bytes): %w", d, len(data), ErrTooLarge)
	}
	return nil
}

// Sink publishes documents. Publish replaces d with data whole (readers
// never see part of it) and returns its revision; Confirmed reports
// whether every reader sees rev now.
type Sink interface {
	Publish(ctx context.Context, d Doc, data []byte) (rev string, err error)
	Confirmed(ctx context.Context, d Doc, rev string) (bool, error)
}

// Remover is a Sink that can withdraw a document (the file removed; on
// Kubernetes the data key dropped, .rev kept as Rev(nil)): readers see
// it missing, as on Docker.
type Remover interface {
	Remove(ctx context.Context, d Doc) error
}

// Laggards is a Sink whose readers confirm later (Kubernetes): Behind
// names the reader pods that don't see rev yet (Err: why the pod
// couldn't be asked, "" = it answered another revision).
type Laggards interface {
	Behind(ctx context.Context, d Doc, rev string) ([]Lag, error)
}

// Lag is one reader pod behind.
type Lag struct {
	Pod string
	Err string
}

// StaleAfter: a reader behind for longer raises published_doc_stale.
const StaleAfter = 120 * time.Second

// TooLarge is a document that wasn't published for its size.
type TooLarge struct {
	Doc  Doc
	Size int
}

// Stale is a document some reader pods still don't see.
type Stale struct {
	Doc   Doc
	Rev   string
	Since time.Time
	Pods  []string
	// Err is the last confirmation error, and each pod's that couldn't
	// be asked ("" = none).
	Err string
}

// pending is a document not confirmed yet: at is the oldest unconfirmed
// publish (kept across republishes, reset only on confirmation), rev
// the latest.
type pending struct {
	rev  string
	at   time.Time
	pods []string
	err  string
}

// Tracker publishes through a Sink and keeps what the doctor reports:
// the documents refused for their size and the readers that lag.
type Tracker struct {
	Sink Sink
	// Now (nil: time.Now); StaleAfter (0: StaleAfter).
	Now        func() time.Time
	StaleAfter time.Duration
	// Max is the largest document handed to the sink (0: no limit, the
	// files of Docker and Podman; Kubernetes: MaxDoc, set by NewTracker
	// for a sink whose readers confirm later).
	Max int

	mu       sync.Mutex
	tooLarge map[Doc]int
	pending  map[Doc]*pending
	// unsynced: documents whose object may differ from the Hub's own
	// copy (a restore or a start-time republish failed): when, and why.
	unsynced map[Doc]unsynced
}

type unsynced struct {
	since time.Time
	err   string
}

// NewTracker returns a Tracker on s.
func NewTracker(s Sink) *Tracker {
	t := &Tracker{Sink: s, tooLarge: map[Doc]int{}, pending: map[Doc]*pending{}, unsynced: map[Doc]unsynced{}}
	if _, ok := s.(Laggards); ok {
		t.Max = MaxDoc
	}
	return t
}

func (t *Tracker) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Tracker) staleAfter() time.Duration {
	if t.StaleAfter > 0 {
		return t.StaleAfter
	}
	return StaleAfter
}

// Precheck is Publish's check alone (recording an oversized document):
// a caller that writes something first (the Hub's own copy) asks it
// before.
func (t *Tracker) Precheck(d Doc, data []byte) error {
	err := Check(d, data, t.Max)
	if errors.Is(err, ErrTooLarge) {
		t.mu.Lock()
		t.tooLarge[d] = len(data)
		t.mu.Unlock()
	}
	return err
}

// Publish checks data (never an empty or oversized document: the sink
// isn't asked, the last good one stays and the size is reported) and
// publishes it; the readers' confirmation is tracked when the sink
// confirms later.
func (t *Tracker) Publish(ctx context.Context, d Doc, data []byte) (string, error) {
	if err := Check(d, data, t.Max); err != nil {
		if errors.Is(err, ErrTooLarge) {
			t.mu.Lock()
			t.tooLarge[d] = len(data)
			t.mu.Unlock()
		}
		return "", err
	}
	rev, err := t.Sink.Publish(ctx, d, data)
	if err != nil {
		return "", err
	}
	t.published(d, rev)
	return rev, nil
}

// Remove withdraws d (the sink must be a Remover).
func (t *Tracker) Remove(ctx context.Context, d Doc) error {
	r, ok := t.Sink.(Remover)
	if !ok {
		return fmt.Errorf("publish: %s can't be removed", d)
	}
	if err := r.Remove(ctx, d); err != nil {
		return err
	}
	t.published(d, Rev(nil))
	return nil
}

// MarkUnsynced records that d's object may differ from the Hub's own
// copy (err: why); reported at once as stale, cleared by the next
// publish of d or ClearUnsynced.
func (t *Tracker) MarkUnsynced(d Doc, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	u, ok := t.unsynced[d]
	if !ok {
		u.since = t.now()
	}
	u.err = err.Error()
	t.unsynced[d] = u
}

// ClearUnsynced: d's object equals the Hub's copy again.
func (t *Tracker) ClearUnsynced(d Doc) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.unsynced, d)
}

func (t *Tracker) published(d Doc, rev string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tooLarge, d)
	delete(t.unsynced, d)
	if _, later := t.Sink.(Laggards); !later {
		return
	}
	if p := t.pending[d]; p != nil {
		// Still unconfirmed: the reader is behind since the oldest
		// publish it hasn't confirmed (a document rewritten every minute
		// must still go stale).
		p.rev = rev
		return
	}
	t.pending[d] = &pending{rev: rev, at: t.now()}
}

// Pending: some document isn't confirmed yet.
func (t *Tracker) Pending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending) > 0
}

// Check asks the sink once about every unconfirmed document: a
// confirmed one is done; one still behind keeps its pods (reported once
// older than StaleAfter).
func (t *Tracker) Check(ctx context.Context) {
	lag, ok := t.Sink.(Laggards)
	if !ok {
		return
	}
	t.mu.Lock()
	type job struct {
		d   Doc
		rev string
	}
	var jobs []job
	for d, p := range t.pending {
		jobs = append(jobs, job{d, p.rev})
	}
	t.mu.Unlock()
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].d < jobs[j].d })
	for _, j := range jobs {
		lags, err := lag.Behind(ctx, j.d, j.rev)
		t.mu.Lock()
		p := t.pending[j.d]
		if p != nil && p.rev == j.rev {
			switch {
			case err != nil:
				p.err = err.Error()
			case len(lags) == 0:
				delete(t.pending, j.d)
			default:
				p.pods, p.err = nil, ""
				var errs []string
				for _, l := range lags {
					p.pods = append(p.pods, l.Pod)
					if l.Err != "" {
						errs = append(errs, l.Pod+": "+l.Err)
					}
				}
				slices.Sort(p.pods)
				slices.Sort(errs)
				p.err = strings.Join(errs, "; ")
			}
		}
		t.mu.Unlock()
	}
}

// Problems are the documents refused for their size and those a reader
// has been behind on for longer than StaleAfter, sorted by document.
func (t *Tracker) Problems() ([]TooLarge, []Stale) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var tl []TooLarge
	for d, n := range t.tooLarge {
		tl = append(tl, TooLarge{Doc: d, Size: n})
	}
	sort.Slice(tl, func(i, j int) bool { return tl[i].Doc < tl[j].Doc })
	byDoc := map[Doc]Stale{}
	now := t.now()
	for d, p := range t.pending {
		if now.Sub(p.at) <= t.staleAfter() || (len(p.pods) == 0 && p.err == "") {
			continue
		}
		byDoc[d] = Stale{Doc: d, Rev: p.rev, Since: p.at, Pods: slices.Clone(p.pods), Err: p.err}
	}
	for d, u := range t.unsynced {
		// One finding per document: the divergence first.
		why := "the published object may differ from the Hub's own copy: " + u.err
		if s, ok := byDoc[d]; ok {
			if s.Err != "" {
				why += "; " + s.Err
			}
			s.Err = why
			byDoc[d] = s
			continue
		}
		byDoc[d] = Stale{Doc: d, Since: u.since, Err: why}
	}
	var st []Stale
	for _, s := range byDoc {
		st = append(st, s)
	}
	sort.Slice(st, func(i, j int) bool { return st[i].Doc < st[j].Doc })
	return tl, st
}
