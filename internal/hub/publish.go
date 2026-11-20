package hub

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/portcullis/hub/internal/doctor"
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

// publishTimeout bounds one publish (one object update).
const publishTimeout = 30 * time.Second

// docSinker is a runtime that publishes documents itself (kube).
type docSinker interface{ DocSink() publish.Sink }

// initPublish picks the sink (caller: New).
func (h *Hub) initPublish() {
	files := publish.FileSink{Dirs: map[publish.Doc]string{}, GID: map[publish.Doc]int{}}
	for _, d := range publish.All {
		if d != publish.VPN {
			files.Dirs[d] = h.cfg.DataDir
		}
	}
	if s, ok := h.rt.(docSinker); ok && h.kubeOn() {
		h.pub = publish.NewTracker(s.DocSink())
		h.pubMirror = &files
		return
	}
	if h.cfg.VPNDocDir != "" {
		files.Dirs[publish.VPN] = h.cfg.VPNDocDir
		files.GID[publish.VPN] = h.cfg.VPNDocGID
	}
	h.pub = publish.NewTracker(files)
}

// publish publishes d (never an empty one, never one over MaxDoc: the
// last good document stays, published_doc_too_large names it).
func (h *Hub) publish(d publish.Doc, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	if _, err := h.pub.Publish(ctx, d, data); err != nil {
		if errors.Is(err, publish.ErrTooLarge) {
			log.Printf("publish: %s is %d bytes, over %d: not published, readers keep the last good one", d, len(data), publish.MaxDoc)
		}
		return err
	}
	if h.pubMirror != nil && h.pubMirror.Has(d) {
		if _, err := h.pubMirror.Publish(ctx, d, data); err != nil {
			return errors.New("published, but the Hub's own copy failed: " + err.Error())
		}
	}
	return nil
}

// unpublish withdraws d (Docker: the file removed; Kubernetes: the data
// key dropped): readers see it missing.
func (h *Hub) unpublish(d publish.Doc) error {
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	if err := h.pub.Remove(ctx, d); err != nil {
		return err
	}
	if h.pubMirror != nil && h.pubMirror.Has(d) {
		return h.pubMirror.Remove(ctx, d)
	}
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
