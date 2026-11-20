package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/publish"
)

// Published documents (contract §4 "On Kubernetes: published documents",
// §8.1, §20.5): every document the Hub writes for another service goes
// through h.publish. Docker and Podman: a FileSink writes today's files
// (hub_data, and vpn_doc for vpn.json) byte for byte. Kubernetes: the
// kube backend's DocSink updates the named object in the core namespace
// and the readers' confirmation is tracked; the same bytes are mirrored
// to the Hub's own volume (hub-state, which no reader mounts) for the
// Hub's own reads (the gate file's last resources, the attributes' hosts,
// the credential store, the MDS serial).

// publishTimeout bounds one publish (one object get and update): under
// the Lease's 15 s, so a stalled API server never outlives a stand-by.
const publishTimeout = 10 * time.Second

// publishContext is a publish's context: the write fence's (cancelled
// the moment the Hub stands by, contract §20.5) with publishTimeout.
func publishContext(parent context.Context) (context.Context, context.CancelFunc) {
	wctx, wcancel := fsutil.WriteContext(parent)
	ctx, cancel := context.WithTimeout(wctx, publishTimeout)
	return ctx, func() { cancel(); wcancel() }
}

// docSinker is a runtime that publishes documents itself (kube).
type docSinker interface{ DocSink() publish.Sink }

// initPublish picks the sink (caller: New). Under Kubernetes a runtime
// without DocSink is refused: readers would never get a document.
func (h *Hub) initPublish() error {
	files := publish.FileSink{Dirs: map[publish.Doc]string{}, GID: map[publish.Doc]int{}}
	for _, d := range publish.All {
		if d != publish.VPN {
			files.Dirs[d] = h.cfg.DataDir
		}
	}
	if h.kubeOn() {
		s, ok := h.rt.(docSinker)
		if !ok {
			return fmt.Errorf("HUB_CONTAINER_RUNTIME=kubernetes: the runtime (%T) can't publish documents", h.rt)
		}
		h.pub = publish.NewTracker(s.DocSink())
		h.pubMirror = &files
		return nil
	}
	if h.cfg.VPNDocDir != "" {
		files.Dirs[publish.VPN] = h.cfg.VPNDocDir
		files.GID[publish.VPN] = h.cfg.VPNDocGID
	}
	h.pub = publish.NewTracker(files)
	return nil
}

// publish publishes d (never an empty one, never one over MaxDoc: the
// last good document stays, published_doc_too_large names it).
//
// Never under h.mu: the publish is a network call on Kubernetes.
func (h *Hub) publish(d publish.Doc, data []byte) error {
	return h.publishWith(context.Background(), d, data)
}

// publishWith is publish within parent (a newer snapshot cancels it).
// Under Kubernetes the Hub's own copy is written first: a failed copy
// publishes nothing, and a failed publish puts the copy back, so what
// the Hub reads back and what readers enforce never diverge.
func (h *Hub) publishWith(parent context.Context, d publish.Doc, data []byte) error {
	ctx, cancel := publishContext(parent)
	defer cancel()
	mu := h.docLock(d)
	mu.Lock()
	defer mu.Unlock()
	if err := h.pub.Precheck(d, data); err != nil {
		if errors.Is(err, publish.ErrTooLarge) {
			log.Printf("publish: %s is %d bytes, over %d: not published, readers keep the last good one", d, len(data), publish.MaxDoc)
		}
		return err
	}
	restore, err := h.copyFirst(d, func() error { _, err := h.pubMirror.Publish(context.Background(), d, data); return err })
	if err != nil {
		return err
	}
	if _, err := h.pub.Publish(ctx, d, data); err != nil {
		restore()
		return err
	}
	h.synced(d)
	return nil
}

// copyFirst writes the Hub's own copy of d (Kubernetes; a no-op
// elsewhere) and returns how to put the previous one back.
func (h *Hub) copyFirst(d publish.Doc, write func() error) (restore func(), err error) {
	if h.pubMirror == nil || !h.pubMirror.Has(d) {
		return func() {}, nil
	}
	p := filepath.Join(h.pubMirror.Dirs[d], publish.Spec(d).Key)
	prev, rerr := os.ReadFile(p)
	absent := errors.Is(rerr, os.ErrNotExist)
	if rerr != nil && !absent {
		return nil, fmt.Errorf("%s: the Hub's own copy can't be read: %w", d, rerr)
	}
	if err := write(); err != nil {
		return nil, fmt.Errorf("%s: the Hub's own copy can't be written (nothing published): %w", d, err)
	}
	return func() {
		var err error
		if absent {
			err = h.pubMirror.Remove(context.Background(), d)
		} else {
			_, err = h.pubMirror.Publish(context.Background(), d, prev)
		}
		if err != nil {
			log.Printf("publish: %s wasn't published and the Hub's own copy couldn't be put back: %v (retried)", d, err)
			h.unsynced(d, err, func() error {
				if absent {
					return h.pubMirror.Remove(context.Background(), d)
				}
				_, err := h.pubMirror.Publish(context.Background(), d, prev)
				return err
			})
		}
	}, nil
}

// unpublish withdraws d (Docker: the file removed; Kubernetes: the data
// key dropped, the Hub's own copy removed first): readers see it
// missing.
func (h *Hub) unpublish(d publish.Doc) error {
	mu := h.docLock(d)
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := publishContext(context.Background())
	defer cancel()
	restore, err := h.copyFirst(d, func() error { return h.pubMirror.Remove(context.Background(), d) })
	if err != nil {
		return err
	}
	if err := h.pub.Remove(ctx, d); err != nil {
		restore()
		return err
	}
	h.synced(d)
	return nil
}

// pubSync is what keeps each document's object equal to the Hub's own
// copy (Kubernetes): a lock per document (a publish, a withdraw and a
// retry of d never interleave) and the retries owed.
type pubSync struct {
	mu    sync.Mutex
	locks map[publish.Doc]*sync.Mutex
	owed  map[publish.Doc]func() error
}

func (h *Hub) docLock(d publish.Doc) *sync.Mutex {
	h.pubSync.mu.Lock()
	defer h.pubSync.mu.Unlock()
	if h.pubSync.locks == nil {
		h.pubSync.locks = map[publish.Doc]*sync.Mutex{}
	}
	m := h.pubSync.locks[d]
	if m == nil {
		m = &sync.Mutex{}
		h.pubSync.locks[d] = m
	}
	return m
}

// unsynced records that d's object and the Hub's copy may differ, and
// the retry that makes them equal (run under d's lock by
// RunPublishConfirm); the doctor reports published_doc_stale.
func (h *Hub) unsynced(d publish.Doc, err error, retry func() error) {
	h.pubSync.mu.Lock()
	if h.pubSync.owed == nil {
		h.pubSync.owed = map[publish.Doc]func() error{}
	}
	h.pubSync.owed[d] = retry
	h.pubSync.mu.Unlock()
	h.pub.MarkUnsynced(d, err)
}

// synced: d's object and copy are equal (a publish or withdraw of d
// succeeded). Caller holds d's lock.
func (h *Hub) synced(d publish.Doc) {
	h.pubSync.mu.Lock()
	delete(h.pubSync.owed, d)
	h.pubSync.mu.Unlock()
	h.pub.ClearUnsynced(d)
}

// retryUnsynced runs every owed retry once.
func (h *Hub) retryUnsynced() {
	h.pubSync.mu.Lock()
	var docs []publish.Doc
	for d := range h.pubSync.owed {
		docs = append(docs, d)
	}
	h.pubSync.mu.Unlock()
	slices.Sort(docs)
	for _, d := range docs {
		mu := h.docLock(d)
		mu.Lock()
		h.pubSync.mu.Lock()
		retry := h.pubSync.owed[d]
		h.pubSync.mu.Unlock()
		if retry != nil {
			if err := retry(); err != nil {
				h.pub.MarkUnsynced(d, err)
			} else {
				h.synced(d)
			}
		}
		mu.Unlock()
	}
}

// RepublishFromCopies makes every published document's object equal to
// the Hub's own copy (Kubernetes; a no-op elsewhere): at start, once
// leading and before serving writes. A copy written before a stand-by,
// a crash or a failed restore cut its object update is what this Hub
// reads back (the credential store, the gate file): its readers get the
// same. A missing copy withdraws the document. One that fails is
// reported (published_doc_stale) and retried by RunPublishConfirm; the
// readers' confirmation follows as for any publish.
func (h *Hub) RepublishFromCopies() {
	if h.pubMirror == nil {
		return
	}
	for _, d := range publish.All {
		if !h.pubMirror.Has(d) {
			continue
		}
		op := func() error {
			ctx, cancel := publishContext(context.Background())
			defer cancel()
			b, err := os.ReadFile(filepath.Join(h.pubMirror.Dirs[d], publish.Spec(d).Key))
			switch {
			case errors.Is(err, os.ErrNotExist):
				return h.pub.Remove(ctx, d)
			case err != nil:
				return err
			}
			_, err = h.pub.Publish(ctx, d, b)
			return err
		}
		mu := h.docLock(d)
		mu.Lock()
		if err := op(); err != nil {
			log.Printf("publish: %s: publishing the Hub's own copy at start failed: %v (retried)", d, err)
			h.unsynced(d, err, op)
		} else {
			h.synced(d)
		}
		mu.Unlock()
	}
}

// RunPublishConfirm asks the readers about every unconfirmed document
// every interval (Kubernetes; a no-op elsewhere) until ctx ends.
func (h *Hub) RunPublishConfirm(ctx context.Context, every time.Duration) {
	if _, ok := h.pub.Sink.(publish.Laggards); !ok {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.retryUnsynced()
		if h.pub.Pending() {
			h.pub.Check(ctx)
		}
	}
}

// publishUserAttributes publishes user-attributes.json (contract §4.1).
func (h *Hub) publishUserAttributes(doc policy.UserAttributesDocument) error {
	b, err := policy.EncodeUserAttributes(doc)
	if err != nil {
		return err
	}
	return h.publish(publish.UserAttributes, b)
}

// doctorPublishedIn is the published documents' problems (nil: none).
func (h *Hub) doctorPublishedIn() *doctor.PublishedIn {
	if h.pub == nil {
		return nil
	}
	tl, st := h.pub.Problems()
	if len(tl) == 0 && len(st) == 0 {
		return nil
	}
	in := &doctor.PublishedIn{}
	for _, d := range tl {
		in.TooLarge = append(in.TooLarge, doctor.PublishedTooLargeIn{Doc: string(d.Doc), Size: d.Size})
	}
	for _, d := range st {
		in.Stale = append(in.Stale, doctor.PublishedStaleIn{Doc: string(d.Doc), Rev: d.Rev, Since: d.Since, Pods: d.Pods, Err: d.Err})
	}
	return in
}
