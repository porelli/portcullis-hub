package doctor

import (
	"fmt"
	"strings"
	"time"
)

// Published documents (contract §4 "On Kubernetes: published
// documents", §14.5; NEW, HA): a document too large to publish, and a
// reader pod still behind on one.
const (
	KindPublishedDocTooLarge = "published_doc_too_large"
	KindPublishedDocStale    = "published_doc_stale"
)

// PublishedKinds are the published-document kinds.
var PublishedKinds = []string{KindPublishedDocTooLarge, KindPublishedDocStale}

// PublishedIn is what the Hub's publisher reports.
type PublishedIn struct {
	TooLarge []PublishedTooLargeIn
	Stale    []PublishedStaleIn
}

// PublishedTooLargeIn is a document not published for its size.
type PublishedTooLargeIn struct {
	Doc  string
	Size int
}

// PublishedStaleIn is a document some reader pods have been behind on
// since Since (the publish).
type PublishedStaleIn struct {
	Doc   string
	Rev   string
	Since time.Time
	Pods  []string
	Err   string
}

func init() {
	for _, k := range PublishedKinds {
		Register(publishedCheck{kind: k})
	}
}

type publishedCheck struct{ kind string }

func (c publishedCheck) Kind() string { return c.kind }

func (c publishedCheck) Run(in *Inputs) []Finding {
	p := in.Published
	if p == nil {
		return nil
	}
	var out []Finding
	switch c.kind {
	case KindPublishedDocTooLarge:
		for _, d := range p.TooLarge {
			out = append(out, Finding{FP: Fingerprint(c.kind, d.Doc), Kind: c.kind, Severity: Problem,
				Title:  fmt.Sprintf("%s.json is too large to publish (%d bytes).", d.Doc, d.Size),
				Why:    fmt.Sprintf("A published document is at most 1 000 000 bytes. The Hub didn't publish this one (%d bytes): its readers keep enforcing the last good one, so the latest changes don't reach them.", d.Size),
				Class:  FixExplain,
				Steps:  []string{"Reduce what the document holds (fewer apps, hosts, people or fields), then save any setting so the Hub publishes again.", "The finding clears once a document of a valid size is published."},
				Inputs: Digest(fmt.Sprint(d.Doc, d.Size))})
		}
	case KindPublishedDocStale:
		for _, d := range p.Stale {
			pods := strings.Join(d.Pods, ", ")
			why := fmt.Sprintf("The Hub published %s.json (revision %s) at %s, and these reader pods still don't see it after 120 s: %s. They keep enforcing the previous document.", d.Doc, d.Rev, d.Since.UTC().Format(time.RFC3339), pods)
			switch {
			case pods == "" && d.Rev == "":
				why = fmt.Sprintf("Since %s, %s. The Hub publishes it again from its own copy every few seconds; until then the readers may enforce another version.", d.Since.UTC().Format(time.RFC3339), d.Err)
			case pods == "":
				why = fmt.Sprintf("The Hub published %s.json (revision %s) at %s and can't confirm that its readers see it: %s.", d.Doc, d.Rev, d.Since.UTC().Format(time.RFC3339), d.Err)
			}
			out = append(out, Finding{FP: Fingerprint(c.kind, d.Doc), Kind: c.kind, Severity: Problem,
				Title:  fmt.Sprintf("Readers of %s.json are behind.", d.Doc),
				Why:    why,
				Class:  FixExplain,
				Steps:  []string{"Check the kubelet on the pods' nodes (core sets --kubelet-arg=sync-frequency=10s) and that the pods mount the published objects.", "Restart the named pods (kubectl -n <core namespace> delete pod <pod>): a new pod mounts the current document. The finding clears when every reader confirms or is gone."},
				Inputs: Digest(d.Doc + " " + d.Rev + " " + pods + " " + d.Err)})
		}
	}
	return out
}
