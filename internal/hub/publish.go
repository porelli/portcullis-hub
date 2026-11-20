package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
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
func (h *Hub) publishWith(parent context.Context, d publish.Doc, data []byte) error {
	ctx, cancel := publishContext(parent)
	defer cancel()
	if _, err := h.pub.Publish(ctx, d, data); err != nil {
		if errors.Is(err, publish.ErrTooLarge) {
			log.Printf("publish: %s is %d bytes, over %d: not published, readers keep the last good one", d, len(data), publish.MaxDoc)
		}
		return err
	}
	h.mirror(d, func() error { _, err := h.pubMirror.Publish(context.Background(), d, data); return err })
	return nil
}

// mirror writes the Hub's own copy of a published document (Kubernetes).
// The object is the authority: readers already have the document, so a
// failed copy is logged and reported by the doctor, never the publish's
// error (callers would take it back).
func (h *Hub) mirror(d publish.Doc, write func() error) {
	if h.pubMirror == nil || !h.pubMirror.Has(d) {
		return
	}
	err := write()
	if err != nil {
		log.Printf("publish: %s is published, but the Hub's own copy failed: %v", d, err)
	}
	h.pub.CopyResult(d, err)
}

// unpublish withdraws d (Docker: the file removed; Kubernetes: the data
// key dropped): readers see it missing.
func (h *Hub) unpublish(d publish.Doc) error {
	ctx, cancel := publishContext(context.Background())
	defer cancel()
	if err := h.pub.Remove(ctx, d); err != nil {
		return err
	}
	h.mirror(d, func() error { return h.pubMirror.Remove(context.Background(), d) })
	return nil
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
	cf := h.pub.CopyProblems()
	if len(tl) == 0 && len(st) == 0 && len(cf) == 0 {
		return nil
	}
	in := &doctor.PublishedIn{}
	for _, d := range tl {
		in.TooLarge = append(in.TooLarge, doctor.PublishedTooLargeIn{Doc: string(d.Doc), Size: d.Size})
	}
	for _, d := range st {
		in.Stale = append(in.Stale, doctor.PublishedStaleIn{Doc: string(d.Doc), Rev: d.Rev, Since: d.Since, Pods: d.Pods, Err: d.Err})
	}
	for _, d := range cf {
		in.CopyFailed = append(in.CopyFailed, doctor.PublishedCopyIn{Doc: string(d.Doc), Err: d.Err})
	}
	return in
}
