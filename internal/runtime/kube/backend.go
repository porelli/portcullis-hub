package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/portcullis/hub/internal/runtime"
)

// ErrReloadDegraded: a reload signal couldn't be sent (no kill in the
// image): the pod was restarted through its Deployment instead (the
// Hub records reload_degraded).
var ErrReloadDegraded = errors.New("reload degraded: the image has no kill, the pod was restarted")

// ErrClusterUnverified wraps every refusal while the cluster guard's
// checks don't hold (503 "the cluster is not verified: <why>").
var ErrClusterUnverified = errors.New("the cluster is not verified")

// UnverifiedError is the guard's refusal.
type UnverifiedError struct{ Why string }

func (e *UnverifiedError) Error() string        { return ErrClusterUnverified.Error() + ": " + e.Why }
func (e *UnverifiedError) Is(target error) bool { return target == ErrClusterUnverified }

// DigestResolver resolves a fully qualified image reference to
// name@sha256:… (digest.go: go-containerregistry, anonymous).
type DigestResolver interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// Execer runs argv in a pod's container with stdin/stdout/stderr
// streams (exec.go: client-go remotecommand; fakes in tests). A non-zero
// exit is an error carrying ExitCode (exitCoder).
type Execer interface {
	Exec(ctx context.Context, namespace, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error
}

// Gate is the cluster guard as the backend sees it: Err is nil while
// every check holds.
type Gate interface{ Err() error }

// Config configures a Backend.
type Config struct {
	Client    kubernetes.Interface
	Dynamic   dynamic.Interface
	Namespace string
	Settings  Settings
	HubImage  string
	Resolver  DigestResolver
	Exec      Execer
	Clock     func() time.Time
	// Guard (nil: unit tests, always verified) gates every method but
	// Kind, Env and Info.
	Guard Gate
	// Poll / UpTimeout / DeliverWait / ReadyWait: the wait loops (zero:
	// 250 ms, 15 min, 90 s, 5 min).
	Poll, UpTimeout, DeliverWait, ReadyWait time.Duration
	// Sleep waits d or until ctx ends (nil: a timer; tests advance a
	// fake clock).
	Sleep func(ctx context.Context, d time.Duration) error
	// Context, RuntimeRoots, APIVersion feed Info.
	Context      string
	RuntimeRoots []string
	BindRoots    []string
	// EdgeNamespace holds the instance's routes ("" = portcullis-edge).
	EdgeNamespace string
}

// Backend serves runtime.Instances on Kubernetes.
type Backend struct {
	cfg Config
	mu  sync.Mutex
	// digests: instance → image ref → digest, kept only after a
	// successful deploy (fail closed: a failed one never pins).
	digests map[string]map[string]string
	// info: the guard's view for Info (set by the guard).
	infoMu sync.Mutex
	info   runtime.Info
}

var _ runtime.Instances = (*Backend)(nil)

// New returns the kube backend.
func New(cfg Config) (*Backend, error) {
	if cfg.Client == nil || cfg.Dynamic == nil || cfg.Namespace == "" {
		return nil, errors.New("kube: a client, a dynamic client and the apps namespace are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.EdgeNamespace == "" {
		cfg.EdgeNamespace = EdgeNamespace
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 250 * time.Millisecond
	}
	if cfg.UpTimeout <= 0 {
		cfg.UpTimeout = 15 * time.Minute
	}
	if cfg.DeliverWait <= 0 {
		cfg.DeliverWait = 90 * time.Second
	}
	if cfg.ReadyWait <= 0 {
		cfg.ReadyWait = 5 * time.Minute
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &Backend{cfg: cfg, digests: map[string]map[string]string{}}, nil
}

func (b *Backend) gate() error {
	if b.cfg.Guard == nil {
		return nil
	}
	return b.cfg.Guard.Err()
}

// deployGate runs the guard's checks right before a deploy (Create, Up:
// contract §6, "before every deploy"); a failed run refuses it.
func (b *Backend) deployGate(ctx context.Context) error {
	if c, ok := b.cfg.Guard.(interface{ Check(context.Context) error }); ok {
		return c.Check(ctx)
	}
	return b.gate()
}

func (b *Backend) Kind() runtime.Kind { return runtime.KindKubernetes }

// Env is empty: no Hub variable reaches a template's interpolation.
func (b *Backend) Env() []string { return []string{} }

// SetInfo records the guard's view (guard.go).
func (b *Backend) SetInfo(i runtime.Info) {
	b.infoMu.Lock()
	defer b.infoMu.Unlock()
	b.info = i
}

// Verified is closed once the cluster guard first verified (never
// without a Guard that has one).
func (b *Backend) Verified() <-chan struct{} {
	if v, ok := b.cfg.Guard.(interface{ Verified() <-chan struct{} }); ok {
		return v.Verified()
	}
	return make(chan struct{})
}

// Info is the guard's view: the pod and service CIDRs as two networks,
// the forbidden roots, the API server's version, the self-test and the
// probe.
func (b *Backend) Info(ctx context.Context) (runtime.Info, error) {
	b.infoMu.Lock()
	i := b.info
	b.infoMu.Unlock()
	if g, ok := b.cfg.Guard.(interface {
		State() (string, string)
		Version() string
	}); ok {
		i.Admission, i.Netpol = g.State()
		i.EngineVersion = g.Version()
	}
	i.Kind = runtime.KindKubernetes
	i.Context = b.cfg.Context
	i.ForbiddenRoots = slices.Clone(b.cfg.RuntimeRoots)
	if err := b.gate(); err != nil {
		i.Verified, i.Why = false, strings.TrimPrefix(err.Error(), ErrClusterUnverified.Error()+": ")
	} else {
		i.Verified, i.Why = true, ""
	}
	i.Networks = nil
	for name, c := range map[string]string{"pod-cidr": b.cfg.Settings.PodCIDR, "service-cidr": b.cfg.Settings.ServiceCIDR} {
		if p, err := parsePrefix(c); err == nil {
			i.Networks = append(i.Networks, runtime.Network{Name: name, Subnets: p})
		}
	}
	slices.SortFunc(i.Networks, func(a, b runtime.Network) int { return strings.Compare(a.Name, b.Name) })
	return i, nil
}

// gvr is the resource of a translated kind.
func gvr(kind string) (schema.GroupVersionResource, bool) {
	r, ok := kinds[kind]
	return r, ok
}

var kinds = map[string]schema.GroupVersionResource{
	"Deployment":            {Group: "apps", Version: "v1", Resource: "deployments"},
	"Job":                   {Group: "batch", Version: "v1", Resource: "jobs"},
	"Service":               {Version: "v1", Resource: "services"},
	"PersistentVolumeClaim": {Version: "v1", Resource: "persistentvolumeclaims"},
	"ConfigMap":             {Version: "v1", Resource: "configmaps"},
	"Secret":                {Version: "v1", Resource: "secrets"},
	"NetworkPolicy":         {Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	"IngressRoute":          {Group: "traefik.io", Version: "v1alpha1", Resource: "ingressroutes"},
	"Middleware":            {Group: "traefik.io", Version: "v1alpha1", Resource: "middlewares"},
}

// downKinds are deleted by Down, in order (PVCs never: §11.2).
var downKinds = []string{"IngressRoute", "Middleware", "Deployment", "Job", "Service", "NetworkPolicy", "ConfigMap", "Secret"}

// apply server-side applies o (field manager portcullis-hub), forcing
// only over an object that carries instance's label: an existing object
// without it is never touched (refused).
func (b *Backend) apply(ctx context.Context, instance string, o *unstructured.Unstructured) error {
	r, ok := gvr(o.GetKind())
	if !ok {
		return fmt.Errorf("kube: no resource for kind %s", o.GetKind())
	}
	if o.GetLabels()[LabelInstance] != instance {
		return fmt.Errorf("kube: %s %s doesn't carry %s=%s: not applied", o.GetKind(), o.GetName(), LabelInstance, instance)
	}
	ns, edge := b.objectNamespace(o)
	if edge && o.GetLabels()[LabelOwner] != OwnerHub {
		return fmt.Errorf("kube: %s %s isn't labelled %s=%s: not applied", o.GetKind(), o.GetName(), LabelOwner, OwnerHub)
	}
	res := b.cfg.Dynamic.Resource(r).Namespace(ns)
	cur, err := res.Get(ctx, o.GetName(), metav1.GetOptions{})
	switch {
	case err == nil:
		if cur.GetLabels()[LabelInstance] != instance || edge && cur.GetLabels()[LabelOwner] != OwnerHub {
			return fmt.Errorf("%s %s exists and isn't instance %s's (label %s=%q): not touching it", strings.ToLower(o.GetKind()), o.GetName(), instance, LabelInstance, cur.GetLabels()[LabelInstance])
		}
	case apierrors.IsNotFound(err):
	default:
		return fmt.Errorf("reading %s %s: %w", strings.ToLower(o.GetKind()), o.GetName(), err)
	}
	data, err := json.Marshal(o.Object)
	if err != nil {
		return err
	}
	force := true
	if _, err := res.Patch(ctx, o.GetName(), ktypes.ApplyPatchType, data, metav1.PatchOptions{FieldManager: FieldManager, Force: &force}); err != nil {
		return fmt.Errorf("applying %s %s: %w", strings.ToLower(o.GetKind()), o.GetName(), err)
	}
	return nil
}

// edgeKinds live in the edge namespace.
var edgeKinds = map[string]bool{"IngressRoute": true, "Middleware": true}

// objectNamespace is where o goes: the edge namespace for routes (true),
// else the apps namespace.
func (b *Backend) objectNamespace(o *unstructured.Unstructured) (string, bool) {
	if edgeKinds[o.GetKind()] {
		return b.cfg.EdgeNamespace, true
	}
	return b.cfg.Namespace, false
}

// input is p's translation input with the digests resolved (cached
// ones first; the new ones returned apart, committed after success).
func (b *Backend) input(ctx context.Context, p runtime.Project) (Input, map[string]string, error) {
	if p.Model == nil {
		return Input{}, nil, fmt.Errorf("%s: the project's model isn't loaded", p.Instance)
	}
	in := Input{Instance: p.Instance, Namespace: b.cfg.Namespace, EdgeNamespace: b.cfg.EdgeNamespace, Model: p.Model, HubImage: b.cfg.HubImage, BindRoots: b.cfg.BindRoots, Settings: b.cfg.Settings, Digests: map[string]string{}}
	if x := p.Inputs; x != nil {
		in.Template, in.TemplateFiles, in.PersonSecrets, in.LanOnly, in.Jobs = x.Template, x.TemplateFiles, x.PersonSecrets, x.LanOnly, x.Jobs
		in.VPNSlot, in.IngressService, in.VPNOnly = x.VPNSlot, x.IngressService, x.VPNOnly
		for _, c := range x.Companions {
			in.Companions = append(in.Companions, Companion{Service: c.Service, Alias: c.Alias, Port: c.Port})
		}
		if x.LocalNetworks != nil {
			in.Settings.LocalNetworks = x.LocalNetworks
		}
		in.AppFiles = map[string]AppFile{}
		for k, v := range x.AppFiles {
			in.AppFiles[k] = AppFile{Name: v.Name, FileName: v.FileName, Data: v.Data, Secrets: v.Secrets, Rev: v.Rev}
		}
	}
	if in.Template == "" {
		in.Template = p.Instance
	}
	b.mu.Lock()
	cached := b.digests[p.Instance]
	b.mu.Unlock()
	fresh := map[string]string{}
	for _, s := range p.Model.Services {
		if _, done := in.Digests[s.Image]; done {
			continue
		}
		if d, ok := cached[s.Image]; ok {
			in.Digests[s.Image] = d
			continue
		}
		if b.cfg.Resolver == nil {
			return Input{}, nil, fmt.Errorf("image %s: no digest resolver", s.Image)
		}
		d, err := b.cfg.Resolver.Resolve(ctx, s.Image)
		if err != nil {
			return Input{}, nil, fmt.Errorf("image %s of service %s doesn't resolve to a digest: %w", s.Image, s.Name, err)
		}
		in.Digests[s.Image], fresh[s.Image] = d, d
	}
	return in, fresh, nil
}

// CachedDigests is a copy of instance's pinned digests (tests, status).
func (b *Backend) CachedDigests(instance string) map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]string{}
	for k, v := range b.digests[instance] {
		out[k] = v
	}
	return out
}

func (b *Backend) plan(ctx context.Context, p runtime.Project) (Plan, map[string]string, error) {
	in, fresh, err := b.input(ctx, p)
	if err != nil {
		return Plan{}, nil, err
	}
	pl, err := Translate(in)
	if err != nil {
		return Plan{}, nil, err
	}
	return pl, fresh, nil
}

// Create applies the instance's objects with every Deployment at 0
// replicas and no Job (nothing starts).
func (b *Backend) Create(ctx context.Context, p runtime.Project) error {
	if err := b.deployGate(ctx); err != nil {
		return err
	}
	pl, _, err := b.plan(ctx, p)
	if err != nil {
		return err
	}
	for i, s := range pl.Steps {
		if i > 0 {
			if s.Objects, err = b.withHostAliases(ctx, p.Instance, pl, s.Objects); err != nil {
				return err
			}
		}
		for _, o := range s.Objects {
			switch o.GetKind() {
			case "Job":
				continue
			case "Deployment":
				o = o.DeepCopy()
				if err := unstructured.SetNestedField(o.Object, int64(0), "spec", "replicas"); err != nil {
					return err
				}
			}
			if err := b.apply(ctx, p.Instance, o); err != nil {
				return err
			}
		}
	}
	return nil
}

// Up applies the plan step by step, waiting after each for what its
// dependents need (readiness, completion); the digests resolved for it
// are pinned only once every step succeeded.
func (b *Backend) Up(ctx context.Context, p runtime.Project, onPull func(svc string, done, total int64, sized bool)) error {
	if err := b.deployGate(ctx); err != nil {
		return err
	}
	pl, fresh, err := b.plan(ctx, p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, b.cfg.UpTimeout)
	defer cancel()
	for i, s := range pl.Steps {
		if i > 0 {
			if s.Objects, err = b.withHostAliases(ctx, p.Instance, pl, s.Objects); err != nil {
				return err
			}
		}
		for _, o := range s.Objects {
			if o.GetKind() == "Job" {
				// A Job's template is immutable: a finished one is
				// replaced (its pods go with it).
				if err := b.replaceJob(ctx, p.Instance, o); err != nil {
					return err
				}
				continue
			}
			if err := b.apply(ctx, p.Instance, o); err != nil {
				return err
			}
		}
		if err := b.wait(ctx, p.Instance, s, onPull); err != nil {
			return err
		}
	}
	b.mu.Lock()
	if b.digests[p.Instance] == nil {
		b.digests[p.Instance] = map[string]string{}
	}
	for k, v := range fresh {
		b.digests[p.Instance][k] = v
	}
	b.mu.Unlock()
	return nil
}

// withHostAliases: objs with every workload's pod given hostAliases for
// the plan's aliases, each at its Service's allocated clusterIP (read
// after the first step applied them). A Service without a clusterIP, or
// one outside the service network, fails the deploy: nothing resolves
// an alias elsewhere.
func (b *Backend) withHostAliases(ctx context.Context, instance string, pl Plan, objs []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	if len(pl.Aliases) == 0 {
		return objs, nil
	}
	svcNet, err := netip.ParsePrefix(b.cfg.Settings.ServiceCIDR)
	if err != nil {
		return nil, fmt.Errorf("aliases: the service network %q: %v", b.cfg.Settings.ServiceCIDR, err)
	}
	var entries []any
	for _, a := range slices.Sorted(mapKeys(pl.Aliases)) {
		svc, err := b.cfg.Dynamic.Resource(kinds["Service"]).Namespace(b.cfg.Namespace).Get(ctx, pl.Aliases[a], metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("alias %s: reading Service %s: %w", a, pl.Aliases[a], err)
		}
		cip, _, _ := unstructured.NestedString(svc.Object, "spec", "clusterIP")
		ip, err := netip.ParseAddr(cip)
		if err != nil || !ip.Is4() || !svcNet.Contains(ip) || ip == svcNet.Masked().Addr() || staticBand(svcNet).Contains(ip) || svc.GetLabels()[LabelInstance] != instance {
			return nil, fmt.Errorf("alias %s: Service %s has no clusterIP in the service network (%q) or isn't the instance's", a, pl.Aliases[a], cip)
		}
		entries = append(entries, map[string]any{"ip": ip.String(), "hostnames": []any{a}})
	}
	out := make([]*unstructured.Unstructured, len(objs))
	for i, o := range objs {
		out[i] = o
		if k := o.GetKind(); k != "Deployment" && k != "Job" {
			continue
		}
		c := o.DeepCopy()
		if err := unstructured.SetNestedSlice(c.Object, entries, "spec", "template", "spec", "hostAliases"); err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

// staticBand is the service network's static band (core's admission:
// the first min(max(16, size/16), 256) addresses, where core's fixed
// clusterIPs live): an alias never resolves there.
func staticBand(svcNet netip.Prefix) netip.Prefix {
	bits := 32 - svcNet.Bits()
	band := min(max(bits-4, 4), 8)
	p, _ := svcNet.Masked().Addr().Prefix(32 - band)
	return p
}

func (b *Backend) replaceJob(ctx context.Context, instance string, o *unstructured.Unstructured) error {
	res := b.cfg.Dynamic.Resource(kinds["Job"]).Namespace(b.cfg.Namespace)
	cur, err := res.Get(ctx, o.GetName(), metav1.GetOptions{})
	if err == nil {
		if cur.GetLabels()[LabelInstance] != instance {
			return fmt.Errorf("job %s exists and isn't instance %s's: not touching it", o.GetName(), instance)
		}
		bg := metav1.DeletePropagationBackground
		if err := res.Delete(ctx, o.GetName(), metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("replacing job %s: %w", o.GetName(), err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("reading job %s: %w", o.GetName(), err)
	}
	return b.apply(ctx, instance, o)
}

// wait waits for step s's workloads (WaitReady: every replica ready;
// WaitComplete: the Job succeeded, a failure is an error).
func (b *Backend) wait(ctx context.Context, instance string, s Step, onPull func(string, int64, int64, bool)) error {
	if s.Wait == WaitNone {
		return nil
	}
	for _, o := range s.Objects {
		for {
			done, err := b.workloadDone(ctx, o, s.Wait)
			if err != nil {
				return err
			}
			if done {
				break
			}
			b.reportPulls(ctx, instance, onPull)
			if err := b.cfg.Sleep(ctx, b.cfg.Poll); err != nil {
				return fmt.Errorf("waiting for %s %s: %w", strings.ToLower(o.GetKind()), o.GetName(), err)
			}
		}
	}
	return nil
}

func (b *Backend) workloadDone(ctx context.Context, o *unstructured.Unstructured, w WaitKind) (bool, error) {
	switch o.GetKind() {
	case "Job":
		j, err := b.cfg.Client.BatchV1().Jobs(b.cfg.Namespace).Get(ctx, o.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("job %s: %w", o.GetName(), err)
		}
		if j.Status.Failed > 0 {
			return false, fmt.Errorf("job %s failed", o.GetName())
		}
		return j.Status.Succeeded > 0, nil
	case "Deployment":
		d, err := b.cfg.Client.AppsV1().Deployments(b.cfg.Namespace).Get(ctx, o.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("deployment %s: %w", o.GetName(), err)
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		if w == WaitComplete {
			return false, fmt.Errorf("deployment %s can't complete (not a job)", o.GetName())
		}
		return d.Status.ObservedGeneration >= d.Generation && d.Status.ReadyReplicas >= want, nil
	}
	return true, nil
}

// reportPulls tells onPull about image pulls of the instance's pods
// (pod events Pulling / Pulled; no byte counts: sized false).
func (b *Backend) reportPulls(ctx context.Context, instance string, onPull func(string, int64, int64, bool)) {
	if onPull == nil {
		return
	}
	pods, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: LabelInstance + "=" + instance})
	if err != nil {
		return
	}
	svcOf := map[string]string{}
	for _, p := range pods.Items {
		svcOf[p.Name] = p.Labels[LabelService]
	}
	evs, err := b.cfg.Client.CoreV1().Events(b.cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for _, e := range evs.Items {
		svc, ok := svcOf[e.InvolvedObject.Name]
		if !ok || e.InvolvedObject.Kind != "Pod" {
			continue
		}
		switch e.Reason {
		case "Pulling":
			onPull(svc, 0, 0, false)
		case "Pulled":
			onPull(svc, 1, 1, false)
		}
	}
}

// Down deletes every object of the instance but its PVCs (compose down
// keeps volumes; PVCs go only through RemoveVolume, §11.4).
func (b *Backend) Down(ctx context.Context, p runtime.Project) error {
	return b.down(ctx, p.Instance)
}

// DownByName works from the labels alone.
func (b *Backend) DownByName(ctx context.Context, name string) error {
	id, ok := strings.CutPrefix(name, runtime.ProjectPrefix)
	if !ok || id == "" {
		return fmt.Errorf("kube: %s is not an instance project", name)
	}
	return b.down(ctx, id)
}

func (b *Backend) down(ctx context.Context, instance string) error {
	if err := b.gate(); err != nil {
		return err
	}
	sel := metav1.ListOptions{LabelSelector: LabelInstance + "=" + instance}
	bg := metav1.DeletePropagationBackground
	var errs []error
	for _, k := range downKinds {
		ns, sl := b.cfg.Namespace, sel
		if edgeKinds[k] {
			// The edge namespace: only the Hub's own objects of the
			// instance (owner=core is never touched).
			ns = b.cfg.EdgeNamespace
			sl = metav1.ListOptions{LabelSelector: LabelInstance + "=" + instance + "," + LabelOwner + "=" + OwnerHub}
		}
		res := b.cfg.Dynamic.Resource(kinds[k]).Namespace(ns)
		l, err := res.List(ctx, sl)
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue // the CRD isn't installed
			}
			errs = append(errs, fmt.Errorf("listing %ss: %w", strings.ToLower(k), err))
			continue
		}
		for _, o := range l.Items {
			if o.GetLabels()[LabelInstance] != instance || edgeKinds[k] && o.GetLabels()[LabelOwner] != OwnerHub {
				continue
			}
			if err := res.Delete(ctx, o.GetName(), metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("deleting %s %s: %w", strings.ToLower(k), o.GetName(), err))
			}
		}
	}
	// Pods left by Jobs and helpers of the instance.
	pods, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).List(ctx, sel)
	if err == nil {
		for _, p := range pods.Items {
			if err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("deleting pod %s: %w", p.Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Pull is a no-op: the kubelet pulls (Up reports it through onPull).
func (b *Backend) Pull(context.Context, string, func(int64, int64, bool)) error { return b.gate() }

// EnsureImage checks that ref resolves (the kubelet pulls it).
func (b *Backend) EnsureImage(ctx context.Context, ref string) error {
	if err := b.gate(); err != nil {
		return err
	}
	if b.cfg.Resolver == nil {
		return fmt.Errorf("image %s: no digest resolver", ref)
	}
	_, err := b.cfg.Resolver.Resolve(ctx, ref)
	return err
}

// unitID is "<pod>/<container>".
func unitID(pod, container string) string { return pod + "/" + container }

func splitID(id string) (string, string, error) {
	pod, c, ok := strings.Cut(id, "/")
	if !ok || pod == "" || c == "" {
		return "", "", fmt.Errorf("kube: unit %q is not <pod>/<container>", id)
	}
	return pod, c, nil
}

func selector(f runtime.Filter) string {
	switch {
	case f.Helper:
		return LabelHelper
	case f.Instance != "":
		s := LabelInstance + "=" + f.Instance
		if f.Service != "" {
			s += "," + LabelService + "=" + sanitizeLabel(f.Service)
		}
		return s
	case f.All:
		return LabelInstance
	}
	return ""
}

// List lists the containers of the selected pods as units.
func (b *Backend) List(ctx context.Context, f runtime.Filter) ([]runtime.Unit, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	pods, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector(f)})
	if err != nil {
		return nil, err
	}
	var out []runtime.Unit
	for _, p := range pods.Items {
		svcOf := map[string]string{}
		json.Unmarshal([]byte(p.Annotations[AnnotationServices]), &svcOf)
		labelsOf := map[string]map[string]string{}
		json.Unmarshal([]byte(p.Annotations[AnnotationComposeLabels]), &labelsOf)
		inst := p.Labels[LabelInstance]
		for _, c := range p.Spec.Containers {
			svc := svcOf[c.Name]
			if svc == "" {
				svc = p.Labels[LabelService]
			}
			if f.Service != "" && svc != f.Service {
				continue
			}
			labels := map[string]string{}
			for k, v := range labelsOf[c.Name] {
				labels[k] = v
			}
			for k, v := range p.Labels {
				labels[k] = v
			}
			u := runtime.Unit{ID: unitID(p.Name, c.Name), Name: unitID(p.Name, c.Name), Instance: inst, Service: svc, Image: c.Image, Labels: labels, Created: p.CreationTimestamp.Unix()}
			if inst != "" {
				u.Project = runtime.ProjectName(inst)
				labels["com.docker.compose.project"] = u.Project
				labels["com.docker.compose.service"] = svc
			}
			if _, ok := p.Labels[LabelHelper]; ok {
				labels["io.portcullis.hub.helper"] = p.Labels[LabelHelper]
			}
			st := containerState(p, c.Name)
			u.State, u.Status = st.Status, statusText(st)
			out = append(out, u)
		}
	}
	return out, nil
}

// containerState maps a pod's container status to the runtime's words.
func containerState(p corev1.Pod, name string) runtime.State {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Name != name {
			continue
		}
		st := runtime.State{}
		switch {
		case cs.State.Running != nil:
			st.Running, st.Status = true, "running"
			switch {
			case cs.Ready:
				st.Health = "healthy"
			case cs.Started != nil && *cs.Started:
				st.Health = "starting"
			default:
				st.Health = "starting"
			}
			if !hasProbe(p, name) {
				st.Health = ""
			} else if !cs.Ready && cs.RestartCount > 0 {
				st.Health = "unhealthy"
			}
		case cs.State.Terminated != nil:
			st.Status, st.ExitCode = "exited", int(cs.State.Terminated.ExitCode)
		case cs.State.Waiting != nil && (cs.State.Waiting.Reason == "CrashLoopBackOff" || cs.RestartCount > 0):
			st.Status = "restarting"
		default:
			st.Status = "created"
		}
		return st
	}
	if p.Status.Phase == corev1.PodSucceeded {
		return runtime.State{Status: "exited"}
	}
	return runtime.State{Status: "created"}
}

func hasProbe(p corev1.Pod, name string) bool {
	for _, c := range p.Spec.Containers {
		if c.Name == name {
			return c.ReadinessProbe != nil
		}
	}
	return false
}

func statusText(st runtime.State) string {
	switch {
	case st.Running && st.Health != "":
		return "Up (" + st.Health + ")"
	case st.Running:
		return "Up"
	case st.Status == "exited":
		return "Exited (" + strconv.Itoa(st.ExitCode) + ")"
	}
	return st.Status
}

func (b *Backend) pod(ctx context.Context, id string) (*corev1.Pod, string, error) {
	if err := b.gate(); err != nil {
		return nil, "", err
	}
	name, c, err := splitID(id)
	if err != nil {
		return nil, "", err
	}
	p, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", nf(err)
	}
	return p, c, nil
}

func (b *Backend) State(ctx context.Context, id string) (runtime.State, error) {
	p, c, err := b.pod(ctx, id)
	if err != nil {
		return runtime.State{}, err
	}
	return containerState(*p, c), nil
}

func (b *Backend) Inspect(ctx context.Context, id string) (runtime.UnitInfo, error) {
	p, cn, err := b.pod(ctx, id)
	if err != nil {
		return runtime.UnitInfo{}, err
	}
	i := runtime.UnitInfo{ID: id, Labels: p.Labels}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Name == cn {
			i.Image = cs.ImageID
		}
	}
	for _, c := range p.Spec.Containers {
		if c.Name != cn {
			continue
		}
		if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
			i.Memory = q.Value()
		}
		if sc := c.SecurityContext; sc != nil {
			i.Privileged = sc.Privileged != nil && *sc.Privileged
			if sc.Capabilities != nil {
				for _, a := range sc.Capabilities.Add {
					i.CapAdd = append(i.CapAdd, string(a))
				}
			}
		}
	}
	if p.Spec.HostPID {
		i.PidMode = "host"
	}
	return i, nil
}

func (b *Backend) Logs(ctx context.Context, id string, tail int, ts bool) ([]byte, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	pod, c, err := splitID(id)
	if err != nil {
		return nil, err
	}
	o := &corev1.PodLogOptions{Container: c, Timestamps: ts}
	if tail > 0 {
		t := int64(tail)
		o.TailLines = &t
	}
	return b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).GetLogs(pod, o).Do(ctx).Raw()
}

// Events watches the selected pods and reports container starts and
// ends as runtime events (Actor.Attributes carry the project label).
func (b *Backend) Events(ctx context.Context, f runtime.Filter, fn func(runtime.Event)) error {
	if err := b.gate(); err != nil {
		return err
	}
	w, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).Watch(ctx, metav1.ListOptions{LabelSelector: selector(f)})
	if err != nil {
		return err
	}
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.ResultChan():
			if !ok {
				return io.EOF
			}
			p, ok := ev.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			action := ""
			switch {
			case ev.Type == "DELETED":
				action = "destroy"
			case p.Status.Phase == corev1.PodRunning:
				action = "start"
			case p.Status.Phase == corev1.PodFailed || p.Status.Phase == corev1.PodSucceeded:
				action = "die"
			default:
				action = "create"
			}
			e := runtime.Event{Type: "container", Action: action, TimeNano: b.cfg.Clock().UnixNano()}
			e.Actor.ID = p.Name
			e.Actor.Attributes = map[string]string{"com.docker.compose.project": runtime.ProjectName(p.Labels[LabelInstance]), "com.docker.compose.service": p.Labels[LabelService]}
			fn(e)
		}
	}
}

// parsePrefix parses one CIDR into a subnet list.
func parsePrefix(s string) ([]netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	return []netip.Prefix{p.Masked()}, nil
}
