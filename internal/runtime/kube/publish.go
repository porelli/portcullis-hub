package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/portcullis/hub/internal/publish"
)

// The published documents on Kubernetes (contract §4 "On Kubernetes:
// published documents"): each is one named object in the core namespace,
// created empty by core's chart; the Hub only gets and updates it (the
// core Role has no create, delete or list there). Every update carries
// the data key and .rev together. The writes go through the backend's
// gated client (GateWrites: a Hub that isn't leading publishes nothing).

// revTimeout bounds one hub rev exec in a reader pod.
const revTimeout = 10 * time.Second

// DocSink is the backend's publish.Sink.
func (b *Backend) DocSink() publish.Sink { return docSink{b} }

type docSink struct{ b *Backend }

var (
	_ publish.Sink     = docSink{}
	_ publish.Remover  = docSink{}
	_ publish.Laggards = docSink{}
)

func (s docSink) Publish(ctx context.Context, d publish.Doc, data []byte) (string, error) {
	if err := publish.Check(d, data, publish.MaxDoc); err != nil {
		return "", err
	}
	if publish.Spec(d).Kind == publish.ConfigMap && !utf8.Valid(data) {
		return "", fmt.Errorf("%s: not UTF-8: not published", d)
	}
	rev := publish.Rev(data)
	return rev, s.update(ctx, d, data, rev)
}

// Remove drops the data key (readers see the file missing, as on Docker
// after a remove) and keeps .rev, the empty document's.
func (s docSink) Remove(ctx context.Context, d publish.Doc) error {
	if !publish.Known(d) {
		return fmt.Errorf("publish: unknown document %q", d)
	}
	return s.update(ctx, d, nil, publish.Rev(nil))
}

// update replaces the object's data with {key: data, .rev: rev} (no key
// when data is nil), retrying a conflict. Only the row's own object is
// ever named.
func (s docSink) update(ctx context.Context, d publish.Doc, data []byte, rev string) error {
	sp := publish.Spec(d)
	core := s.b.cfg.Client.CoreV1()
	nsName := s.b.cfg.CoreNamespace
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		switch sp.Kind {
		case publish.Secret:
			cur, err := core.Secrets(nsName).Get(ctx, sp.Object, metav1.GetOptions{})
			if err != nil {
				return notCreated(sp.Object, err)
			}
			cur.Data = map[string][]byte{".rev": []byte(rev)}
			if data != nil {
				cur.Data[sp.Key] = data
			}
			cur.StringData = nil
			_, err = core.Secrets(nsName).Update(ctx, cur, metav1.UpdateOptions{FieldManager: FieldManager})
			return err
		default:
			cur, err := core.ConfigMaps(nsName).Get(ctx, sp.Object, metav1.GetOptions{})
			if err != nil {
				return notCreated(sp.Object, err)
			}
			cur.Data = map[string]string{".rev": rev}
			if data != nil {
				cur.Data[sp.Key] = string(data)
			}
			cur.BinaryData = nil
			_, err = core.ConfigMaps(nsName).Update(ctx, cur, metav1.UpdateOptions{FieldManager: FieldManager})
			return err
		}
	})
}

// notCreated: the chart creates the objects; the Hub never does.
func notCreated(name string, err error) error {
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%s is missing (core's chart creates it; run ./portcullis upgrade): %w", name, err)
	}
	return err
}

func (s docSink) Confirmed(ctx context.Context, d publish.Doc, rev string) (bool, error) {
	behind, err := s.Behind(ctx, d, rev)
	return err == nil && len(behind) == 0, err
}

// revParallel bounds the hub rev execs of one Behind.
const revParallel = 4

// Behind runs `/portcullis-bin/hub rev <mount> <doc>` in every running
// reader pod of d (label portcullis.io/component in the row's readers),
// at most revParallel at once, and names, sorted, those that don't print
// rev (with the exec's error when it failed). A pod being deleted or
// not running yet isn't asked (it mounts the latest object when it
// starts).
func (s docSink) Behind(ctx context.Context, d publish.Doc, rev string) ([]publish.Lag, error) {
	if !publish.Known(d) {
		return nil, fmt.Errorf("publish: unknown document %q", d)
	}
	if s.b.cfg.Exec == nil {
		return nil, errors.New("kube: no exec transport")
	}
	sp := publish.Spec(d)
	sel := LabelComponent + " in (" + strings.Join(sp.Readers, ",") + ")"
	pods, err := s.b.cfg.Client.CoreV1().Pods(s.b.cfg.CoreNamespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		behind []publish.Lag
		slots  = make(chan struct{}, revParallel)
	)
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || !isReader(p, sp.Readers) {
			continue
		}
		wg.Add(1)
		slots <- struct{}{}
		go func(p corev1.Pod) {
			defer func() { <-slots; wg.Done() }()
			got, err := s.rev(ctx, p, sp, d)
			if err == nil && got == rev {
				return
			}
			l := publish.Lag{Pod: p.Name}
			if err != nil {
				l.Err = clip(err.Error(), 200)
			}
			mu.Lock()
			behind = append(behind, l)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(behind, func(i, j int) bool { return behind[i].Pod < behind[j].Pod })
	return behind, nil
}

// isReader double-checks the selector's answer (the admission policy
// admits the exec only in a pod named after a reader component).
func isReader(p corev1.Pod, readers []string) bool {
	c := p.Labels[LabelComponent]
	for _, r := range readers {
		if c == r && strings.HasPrefix(p.Name, r+"-") {
			return true
		}
	}
	return false
}

// rev is what the pod's reader container sees as d's revision.
func (s docSink) rev(ctx context.Context, p corev1.Pod, sp publish.DocSpec, d publish.Doc) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, revTimeout)
	defer cancel()
	var out bytes.Buffer
	err := s.b.cfg.Exec.Exec(ctx, s.b.cfg.CoreNamespace, p.Name, readerContainer(p), []string{"/portcullis-bin/hub", "rev", sp.Mount, string(d)}, nil, &limitedBuf{&out, 256}, &limitedBuf{&bytes.Buffer{}, 256})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

// readerContainer is the container that mounts /portcullis-bin (the
// first container when none does).
func readerContainer(p corev1.Pod) string {
	for _, c := range p.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.MountPath == "/portcullis-bin" {
				return c.Name
			}
		}
	}
	if len(p.Spec.Containers) > 0 {
		return p.Spec.Containers[0].Name
	}
	return ""
}

// limitedBuf keeps at most n bytes (a revision is 16).
type limitedBuf struct {
	b *bytes.Buffer
	n int
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}
