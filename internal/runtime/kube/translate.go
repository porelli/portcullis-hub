// Package kube is the Kubernetes backend of runtime.Instances: a pure
// compose → Kubernetes translator (translate.go, golden-tested), the
// apply/status/exec/delivery backend over client-go, helper pods, the
// exposure objects (IngressRoutes, Middlewares, NetworkPolicies) and the
// cluster guard.
package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/portcullis/hub/internal/templates"
)

// ErrRefused is a translation that can't be represented: nothing is
// applied for the instance.
type ErrRefused struct{ Reason string }

func (e *ErrRefused) Error() string { return e.Reason }

func refused(format string, a ...any) error { return &ErrRefused{Reason: fmt.Sprintf(format, a...)} }

// MaxObject is the API's object size limit (etcd's request limit).
const MaxObject = 1 << 20

// Settings are the cluster facts the translation needs (core.env).
type Settings struct {
	PodCIDR, ServiceCIDR string
	TraefikServiceIP     string
	WGEdgeServiceIP      string
	Domain               string
	CorePorts            []int
	LocalNetworks        []string
	// NodeAddresses are the node IPs (PORTCULLIS_KUBE_NODE_ADDRESSES):
	// egress excludes them but for 80/443.
	NodeAddresses []string
}

// AppFile is a data file (§13.7) bound into the instance: its name, the
// data file's bytes and its secrets file's (nil: none).
type AppFile struct {
	// Name is the data file's name, FileName its file (<name>.json or
	// <name>.tsv; "" = <name>.json).
	Name, FileName string
	Data           []byte
	Secrets []byte
	// Rev is the delivery revision (the objects' .rev key).
	Rev string
}

// Input is one instance's translation input.
type Input struct {
	Instance, Template, Namespace string
	Model                         *types.Project
	// Digests: image reference → name@sha256:… (unresolved = refused).
	Digests map[string]string
	// TemplateFiles: path relative to the template directory → content
	// (the files compose binds from ./templates/<template>/).
	TemplateFiles map[string][]byte
	// AppFiles: a bind source (as in the model) → its data file.
	AppFiles map[string]AppFile
	// PersonSecrets: person_secret option key → <user>.nt → content.
	PersonSecrets map[string]map[string][]byte
	// LanOnly: published ports (manifest lan_only).
	LanOnly   map[int]bool
	BindRoots []string
	// HubImage is HUB_SELF_IMAGE (portcullis-bin, helpers).
	HubImage string
	// VPNSlot / IngressService: a wired VPN provider's slot and the
	// service whose pod is its ingress.
	VPNSlot        *int
	IngressService string
	Settings       Settings
	// Jobs are the instance's one-off jobs (manifest jobs and
	// service_completed_successfully targets).
	Jobs map[string]bool
}

// WaitKind is what Up waits for after a step.
type WaitKind int

const (
	WaitNone WaitKind = iota
	WaitReady
	WaitComplete
)

// Step is objects applied together, then waited for.
type Step struct {
	Objects []*unstructured.Unstructured
	Wait    WaitKind
}

// Plan is an instance's objects in apply order.
type Plan struct {
	Steps []Step
	// Services: compose service → its workload object name (the pod's
	// owner), the containers it runs (the service first).
	Services map[string]string
}

// Objects are every object of p, in order.
func (p Plan) Objects() []*unstructured.Unstructured {
	var out []*unstructured.Unstructured
	for _, s := range p.Steps {
		out = append(out, s.Objects...)
	}
	return out
}

// Translate translates in into a Plan, or refuses (*ErrRefused).
func Translate(in Input) (Plan, error) {
	t := &translator{in: in, names: map[string]string{}, done: map[string]bool{}}
	return t.run()
}

type translator struct {
	in    Input
	names map[string]string // object name → the compose name it came from
	done  map[string]bool   // shared objects already made
	// shared objects (secrets, config maps, PVCs), in order.
	shared   []*unstructured.Unstructured
	tplCM    string
	tplItems map[string]string // template path → ConfigMap key
}

func (t *translator) claim(kind, name, from string) error {
	k := kind + "/" + name
	if prev, ok := t.names[k]; ok && prev != from {
		return refused("%s and %s give the same object name %s", prev, from, name)
	}
	t.names[k] = from
	return nil
}

func (t *translator) labels(service string) map[string]string {
	l := map[string]string{LabelInstance: t.in.Instance}
	if service != "" {
		l[LabelService] = service
	}
	return l
}

func meta(name, ns string, labels map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}
}

func (t *translator) run() (Plan, error) {
	m := t.in.Model
	if m == nil {
		return Plan{}, refused("%s: no compose model", t.in.Instance)
	}
	// RuntimeCompat's rules first: the translator refuses exactly what
	// it refuses (TestTranslatorRefusesWhatCompatRefuses).
	if err := t.compat(); err != nil {
		return Plan{}, err
	}
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range m.Services {
			if !yield(n) {
				return
			}
		}
	})
	// Pods: a service with network_mode service:<x> is a container in
	// <x>'s pod.
	podOf := map[string]string{}
	for _, n := range names {
		podOf[n] = n
		if x, ok := strings.CutPrefix(m.Services[n].NetworkMode, types.NetworkModeServicePrefix); ok {
			if _, exists := m.Services[x]; !exists {
				return Plan{}, refused("service %s shares the network of %s, which isn't a service", n, x)
			}
			podOf[n] = x
		}
	}
	for _, n := range names {
		if podOf[podOf[n]] != podOf[n] {
			return Plan{}, refused("service %s shares the network of %s, which shares another's", n, podOf[n])
		}
	}
	for _, n := range names {
		if podOf[n] != n {
			continue
		}
		if err := t.claim("workload", ObjectName(t.in.Instance, n), "service "+n); err != nil {
			return Plan{}, err
		}
	}
	if err := t.envSecret(); err != nil {
		return Plan{}, err
	}
	if err := t.templateFiles(); err != nil {
		return Plan{}, err
	}
	workloads := map[string]*unstructured.Unstructured{}
	var services []*unstructured.Unstructured
	for _, n := range names {
		if podOf[n] != n {
			continue
		}
		var members []string
		for _, o := range names {
			if o != n && podOf[o] == n {
				members = append(members, o)
			}
		}
		w, err := t.workload(n, members)
		if err != nil {
			return Plan{}, err
		}
		workloads[n] = w
		svcs, err := t.servicePorts(n, append([]string{n}, members...))
		if err != nil {
			return Plan{}, err
		}
		services = append(services, svcs...)
	}
	for _, o := range append(append([]*unstructured.Unstructured{}, t.shared...), services...) {
		if err := checkSize(o); err != nil {
			return Plan{}, err
		}
	}
	for _, w := range workloads {
		if err := checkSize(w); err != nil {
			return Plan{}, err
		}
	}
	plan := Plan{Services: map[string]string{}}
	for _, n := range names {
		plan.Services[n] = ObjectName(t.in.Instance, podOf[n])
	}
	plan.Steps = append(plan.Steps, Step{Objects: append(t.shared, services...)})
	order, waits, err := t.order(names, podOf)
	if err != nil {
		return Plan{}, err
	}
	for _, n := range order {
		plan.Steps = append(plan.Steps, Step{Objects: []*unstructured.Unstructured{workloads[n]}, Wait: waits[n]})
	}
	return plan, nil
}

// compat runs templates' Kubernetes rules on the model's services.
func (t *translator) compat() error {
	m := t.in.Model
	for _, n := range slices.Sorted(mapKeys(m.Services)) {
		s := m.Services[n]
		switch {
		case s.NetworkMode == "host":
			return refused("service %s uses network_mode: host (not on Kubernetes)", n)
		case s.Privileged:
			return refused("service %s is privileged (not on Kubernetes)", n)
		case s.Pid == "host":
			return refused("service %s shares the host's pid namespace (not on Kubernetes)", n)
		case s.Ipc == "host":
			return refused("service %s shares the host's ipc namespace (not on Kubernetes)", n)
		case len(s.ExtraHosts) > 0:
			return refused("service %s sets extra_hosts (not on Kubernetes)", n)
		case s.Scale != nil && *s.Scale > 1:
			return refused("service %s sets replicas above 1 (not on Kubernetes)", n)
		}
		for _, d := range s.Devices {
			switch d.Source {
			case "/dev/null":
			case "/dev/net/tun":
				return refused("service %s uses TUN/NET_ADMIN (not on Kubernetes; prefer a userspace mode)", n)
			default:
				return refused("service %s passes host devices (not on Kubernetes)", n)
			}
		}
		for _, c := range s.CapAdd {
			c = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
			if c == "NET_ADMIN" {
				return refused("service %s uses TUN/NET_ADMIN (not on Kubernetes; prefer a userspace mode)", n)
			}
			if !slices.Contains(templates.KubeBaselineCaps, c) {
				return refused("service %s adds %s, outside the Kubernetes baseline", n, c)
			}
		}
		if s.User != "" {
			if _, _, err := numericUser(s.User); err != nil {
				return refused("service %s runs as user %s: Kubernetes needs a numeric uid", n, s.User)
			}
		}
		for _, p := range s.Ports {
			if pub, _ := strconv.Atoi(p.Published); pub > 0 && slices.Contains(t.corePorts(), pub) {
				return refused("service %s publishes port %d, a core port", n, pub)
			}
		}
	}
	return nil
}

func (t *translator) corePorts() []int {
	if len(t.in.Settings.CorePorts) > 0 {
		return t.in.Settings.CorePorts
	}
	return templates.KubeCorePorts(nil)
}

func mapKeys[K comparable, V any](m map[K]V) func(func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// numericUser parses "uid[:gid]" (numeric only).
func numericUser(u string) (int64, *int64, error) {
	us, gs, hasG := strings.Cut(u, ":")
	uid, err := strconv.ParseInt(us, 10, 64)
	if err != nil || uid < 0 || uid > math.MaxInt32 {
		return 0, nil, fmt.Errorf("not numeric")
	}
	if !hasG {
		return uid, nil, nil
	}
	gid, err := strconv.ParseInt(gs, 10, 64)
	if err != nil || gid < 0 || gid > math.MaxInt32 {
		return 0, nil, fmt.Errorf("not numeric")
	}
	return uid, &gid, nil
}

// envSecret is the instance's env Secret (the services' interpolated
// environment): one key per service and variable ("<service>.<VAR>"),
// read by secretKeyRef, so each service gets exactly its own variables
// and no value appears in a pod spec.
func (t *translator) envSecret() error {
	data := map[string][]byte{}
	for svc, s := range t.in.Model.Services {
		for k, v := range s.Environment {
			if v != nil && !(t.in.VPNSlot != nil && k == "PORTCULLIS_VPN_EDGE") {
				data[envKey(svc, k)] = []byte(*v)
			}
		}
	}
	if t.in.VPNSlot != nil {
		edge := t.in.Settings.WGEdgeServiceIP + ":" + strconv.Itoa(9001+*t.in.VPNSlot)
		for _, svc := range t.vpnPodServices() {
			data[envKey(svc, "PORTCULLIS_VPN_EDGE")] = []byte(edge)
		}
	}
	name := EnvSecretName(t.in.Instance)
	if err := t.claim("secret", name, "the instance env"); err != nil {
		return err
	}
	s := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta(name, t.in.Namespace, t.labels("")), Type: corev1.SecretTypeOpaque, Data: data}
	return t.addShared(s)
}

// vpnPodServices are the services of the VPN ingress service's pod.
func (t *translator) vpnPodServices() []string {
	ing := t.in.IngressService
	out := []string{ing}
	for n, s := range t.in.Model.Services {
		if s.NetworkMode == types.NetworkModeServicePrefix+ing {
			out = append(out, n)
		}
	}
	slices.Sort(out[1:])
	return out
}

func envKey(service, name string) string { return sanitizeKey(service) + "." + name }

// sanitizeKey keeps a ConfigMap/Secret key's allowed characters.
func sanitizeKey(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
}

func (t *translator) addShared(o any) error {
	u, err := toUnstructured(o)
	if err != nil {
		return err
	}
	t.shared = append(t.shared, u)
	return nil
}

// templateFiles is the ConfigMap of the template files compose binds
// (at most 1 MiB in all).
func (t *translator) templateFiles() error {
	if len(t.in.TemplateFiles) == 0 {
		return nil
	}
	total := 0
	h := sha256.New()
	keys := slices.Sorted(mapKeys(t.in.TemplateFiles))
	data := map[string]string{}
	bin := map[string][]byte{}
	t.tplItems = map[string]string{}
	for i, p := range keys {
		b := t.in.TemplateFiles[p]
		total += len(b) + len(p)
		fmt.Fprintf(h, "%s\x00%d\x00", p, len(b))
		h.Write(b)
		k := fmt.Sprintf("f%03d-%s", i, sanitizeKey(path.Base(p)))
		if len(k) > 250 {
			k = k[:250]
		}
		t.tplItems[p] = k
		if isUTF8(b) {
			data[k] = string(b)
		} else {
			bin[k] = b
		}
	}
	if total > MaxObject-16<<10 {
		return refused("template files for %s exceed 1 MiB", t.in.Template)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	t.tplCM = TemplateFilesName(t.in.Template, sum)
	if err := t.claim("configmap", t.tplCM, "the template files"); err != nil {
		return err
	}
	cm := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta(t.tplCM, t.in.Namespace, t.labels("")), Data: data}
	if len(bin) > 0 {
		cm.BinaryData = bin
	}
	return t.addShared(cm)
}

func isUTF8(b []byte) bool { return strings.ToValidUTF8(string(b), "�") == string(b) && !strings.ContainsRune(string(b), 0) }

func checkSize(o *unstructured.Unstructured) error {
	b, err := json.Marshal(o.Object)
	if err != nil {
		return err
	}
	if len(b) > MaxObject {
		return refused("%s %s exceeds 1 MiB", strings.ToLower(o.GetKind()), o.GetName())
	}
	return nil
}

// order is the workloads' apply order (depends_on, a topological order,
// names breaking ties) and what each step waits for.
func (t *translator) order(names []string, podOf map[string]string) ([]string, map[string]WaitKind, error) {
	m := t.in.Model
	deps := map[string]map[string]bool{}
	waits := map[string]WaitKind{}
	for _, n := range names {
		p := podOf[n]
		if deps[p] == nil {
			deps[p] = map[string]bool{}
		}
		for d, c := range m.Services[n].DependsOn {
			if _, ok := m.Services[d]; !ok {
				continue // a profile left it off
			}
			dp := podOf[d]
			if dp == p {
				continue
			}
			deps[p][dp] = true
			switch c.Condition {
			case types.ServiceConditionCompletedSuccessfully:
				waits[dp] = WaitComplete
			case types.ServiceConditionHealthy:
				if waits[dp] != WaitComplete {
					waits[dp] = WaitReady
				}
			}
		}
	}
	var out []string
	done := map[string]bool{}
	for len(out) < len(deps) {
		progress := false
		for _, n := range names {
			if podOf[n] != n || done[n] {
				continue
			}
			ready := true
			for d := range deps[n] {
				ready = ready && done[d]
			}
			if ready {
				out = append(out, n)
				done[n] = true
				progress = true
			}
		}
		if !progress {
			return nil, nil, refused("the services' depends_on form a cycle")
		}
	}
	return out, waits, nil
}

// toUnstructured converts a typed object.
func toUnstructured(o any) (*unstructured.Unstructured, error) {
	m, err := defaultConverter(o)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: m}, nil
}

// isJob: a one-off job (manifest jobs, service_completed_successfully
// targets, restart "no").
func (t *translator) isJob(n string) bool {
	if t.in.Jobs[n] {
		return true
	}
	return t.in.Model.Services[n].Restart == types.RestartPolicyNo
}

func (t *translator) workload(n string, members []string) (*unstructured.Unstructured, error) {
	m := t.in.Model
	s := m.Services[n]
	ps := &podSpec{t: t, pod: n}
	if err := ps.container(n, s, true); err != nil {
		return nil, err
	}
	for _, o := range members {
		if err := ps.container(o, m.Services[o], false); err != nil {
			return nil, err
		}
	}
	spec := ps.finish()
	labels := t.labels(n)
	podLabels := t.labels(n)
	for _, net := range ps.networks {
		podLabels[LabelNetPrefix+sanitize(net)] = "true"
	}
	if ps.egress {
		podLabels[LabelEgress] = "true"
	}
	if t.in.VPNSlot != nil && n == t.in.IngressService {
		podLabels[LabelVPNSlot] = strconv.Itoa(*t.in.VPNSlot)
	}
	// Compose labels and the service of each container: annotations
	// (per container), never labels.
	labelsOf, svcOf := map[string]map[string]string{}, map[string]string{}
	for _, svc := range append([]string{n}, members...) {
		svcOf[containerName(svc)] = svc
		if l := m.Services[svc].Labels; len(l) > 0 {
			labelsOf[containerName(svc)] = map[string]string(l)
		}
	}
	ann := map[string]string{}
	b, _ := json.Marshal(svcOf)
	ann[AnnotationServices] = string(b)
	if len(labelsOf) > 0 {
		b, _ := json.Marshal(labelsOf)
		ann[AnnotationComposeLabels] = string(b)
	}
	tmpl := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: ann}, Spec: spec}
	name := ObjectName(t.in.Instance, n)
	if t.isJob(n) {
		tmpl.Spec.RestartPolicy = corev1.RestartPolicyNever
		zero := int32(0)
		j := &batchv1.Job{TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}, ObjectMeta: meta(name, t.in.Namespace, labels),
			Spec: batchv1.JobSpec{BackoffLimit: &zero, Template: tmpl}}
		return toUnstructured(j)
	}
	replicas := int32(1)
	if s.Scale != nil && *s.Scale == 0 {
		replicas = 0
	}
	d := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta(name, t.in.Namespace, labels),
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: t.labels(n)},
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Template: tmpl,
		}}
	return toUnstructured(d)
}

// podSpec collects one pod's containers and volumes.
type podSpec struct {
	t          *translator
	pod        string
	containers []corev1.Container
	inits      []corev1.Container
	volumes    []corev1.Volume
	volNames   map[string]bool
	networks   []string
	egress     bool
	needBin    bool
	seeds      int
	sc         *corev1.PodSecurityContext
	grace      *int64
}

func (p *podSpec) addVolume(v corev1.Volume) {
	if p.volNames == nil {
		p.volNames = map[string]bool{}
	}
	if p.volNames[v.Name] {
		return
	}
	p.volNames[v.Name] = true
	p.volumes = append(p.volumes, v)
}

func seconds(d *types.Duration, def time.Duration) int32 {
	v := def
	if d != nil {
		v = time.Duration(*d)
	}
	s := int32(math.Ceil(v.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}

// probes maps a compose healthcheck (K17).
func probes(h *types.HealthCheckConfig) (ready, live, startup *corev1.Probe) {
	if h == nil || h.Disable || len(h.Test) == 0 || h.Test[0] == "NONE" {
		return nil, nil, nil
	}
	var cmd []string
	switch h.Test[0] {
	case "CMD-SHELL":
		cmd = []string{"sh", "-c", strings.Join(h.Test[1:], " ")}
	case "CMD":
		cmd = append([]string(nil), h.Test[1:]...)
	default:
		cmd = []string{"sh", "-c", strings.Join(h.Test, " ")}
	}
	interval := seconds(h.Interval, 30*time.Second)
	timeout := seconds(h.Timeout, 30*time.Second)
	retries := int32(3)
	if h.Retries != nil {
		retries = int32(*h.Retries)
	}
	mk := func(fail int32) *corev1.Probe {
		return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: cmd}},
			PeriodSeconds: interval, TimeoutSeconds: timeout, FailureThreshold: fail}
	}
	ready, live = mk(retries), mk(retries*2)
	if h.StartPeriod != nil && time.Duration(*h.StartPeriod) > 0 {
		sp := time.Duration(*h.StartPeriod).Seconds()
		startup = mk(int32(math.Ceil(sp/float64(interval))) + retries)
	}
	return ready, live, startup
}

func (p *podSpec) container(n string, s types.ServiceConfig, main bool) error {
	t := p.t
	img, ok := t.in.Digests[s.Image]
	if !ok || img == "" {
		return refused("service %s: image %s is not resolved to a digest", n, s.Image)
	}
	c := corev1.Container{Name: containerName(n), Image: img, ImagePullPolicy: corev1.PullIfNotPresent}
	if len(s.Entrypoint) > 0 {
		c.Command = append([]string(nil), s.Entrypoint...)
	}
	if len(s.Command) > 0 {
		c.Args = append([]string(nil), s.Command...)
	}
	c.WorkingDir = s.WorkingDir
	vpnPod := t.in.VPNSlot != nil && slices.Contains(t.vpnPodServices(), n)
	for _, k := range slices.Sorted(mapKeys(s.Environment)) {
		if s.Environment[k] == nil || vpnPod && k == "PORTCULLIS_VPN_EDGE" {
			continue
		}
		c.Env = append(c.Env, corev1.EnvVar{Name: k, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: EnvSecretName(t.in.Instance)}, Key: envKey(n, k)}}})
	}
	if vpnPod {
		c.Env = append(c.Env, corev1.EnvVar{Name: "PORTCULLIS_VPN_EDGE", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: EnvSecretName(t.in.Instance)}, Key: envKey(n, "PORTCULLIS_VPN_EDGE")}}})
	}
	// Security context.
	sc := &corev1.SecurityContext{}
	var uid int64 = -1
	var gid *int64
	if s.User != "" {
		u, g, err := numericUser(s.User)
		if err != nil {
			return refused("service %s runs as user %s: Kubernetes needs a numeric uid", n, s.User)
		}
		uid, gid = u, g
		sc.RunAsUser = &u
		if g != nil {
			sc.RunAsGroup = g
		}
	}
	caps := &corev1.Capabilities{}
	for _, d := range s.CapDrop {
		caps.Drop = append(caps.Drop, corev1.Capability(strings.TrimPrefix(strings.ToUpper(d), "CAP_")))
	}
	slices.SortFunc(caps.Drop, func(a, b corev1.Capability) int {
		switch {
		case a == "ALL":
			return -1
		case b == "ALL":
			return 1
		}
		return strings.Compare(string(a), string(b))
	})
	for _, a := range s.CapAdd {
		caps.Add = append(caps.Add, corev1.Capability(strings.TrimPrefix(strings.ToUpper(a), "CAP_")))
	}
	if len(caps.Add)+len(caps.Drop) > 0 {
		sc.Capabilities = caps
	}
	if s.ReadOnly {
		ro := true
		sc.ReadOnlyRootFilesystem = &ro
	}
	for _, o := range s.SecurityOpt {
		if o == "no-new-privileges:true" || o == "no-new-privileges" || o == "no-new-privileges=true" {
			f := false
			sc.AllowPrivilegeEscalation = &f
		}
	}
	c.SecurityContext = sc
	if main {
		p.sc = &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
		for _, g := range s.GroupAdd {
			v, err := strconv.ParseInt(g, 10, 64)
			if err != nil {
				return refused("service %s adds group %s: Kubernetes needs a numeric gid", n, g)
			}
			p.sc.SupplementalGroups = append(p.sc.SupplementalGroups, v)
		}
		// fsGroup: the service's gid (its uid without one), so the 0440
		// Secret and ConfigMap mounts are readable by that service only.
		if gid != nil {
			p.sc.FSGroup = gid
		} else if uid >= 0 {
			u := uid
			p.sc.FSGroup = &u
		}
		if s.StopGracePeriod != nil {
			g := int64(math.Ceil(time.Duration(*s.StopGracePeriod).Seconds()))
			p.grace = &g
		}
	}
	// Probes.
	c.ReadinessProbe, c.LivenessProbe, c.StartupProbe = probes(s.HealthCheck)
	if s.StopSignal != "" {
		c.Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"kill", "-s", strings.TrimPrefix(s.StopSignal, "SIG"), "1"}}}}
	}
	// Memory.
	mem := s.MemLimit
	if s.Deploy != nil && s.Deploy.Resources.Limits != nil && s.Deploy.Resources.Limits.MemoryBytes > 0 {
		mem = s.Deploy.Resources.Limits.MemoryBytes
	}
	if mem > 0 {
		q := *resource.NewQuantity(int64(mem), resource.BinarySI)
		c.Resources = corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q}, Requests: corev1.ResourceList{corev1.ResourceMemory: q}}
	}
	// Networks.
	for _, net := range slices.Sorted(mapKeys(s.Networks)) {
		if !slices.Contains(p.networks, net) {
			p.networks = append(p.networks, net)
		}
		if nc, ok := t.in.Model.Networks[net]; ok && !bool(nc.External) && !nc.Internal {
			p.egress = true
		}
	}
	if len(s.Networks) == 0 && s.NetworkMode == "" {
		// compose's implicit default network (not internal).
		if !slices.Contains(p.networks, "default") {
			p.networks = append(p.networks, "default")
		}
		p.egress = true
	}
	// tmpfs and shm.
	for i, tf := range s.Tmpfs {
		target, opts, _ := strings.Cut(tf, ":")
		ed := &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}
		for _, o := range strings.Split(opts, ",") {
			if v, ok := strings.CutPrefix(o, "size="); ok {
				if q, err := resource.ParseQuantity(sizeQuantity(v)); err == nil {
					ed.SizeLimit = &q
				}
			}
		}
		vn := fmt.Sprintf("tmpfs-%s-%d", containerName(n), i)
		p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{EmptyDir: ed}})
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: target})
	}
	if s.ShmSize > 0 {
		q := *resource.NewQuantity(int64(s.ShmSize), resource.BinarySI)
		vn := "shm-" + containerName(n)
		p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: &q}}})
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: "/dev/shm"})
	}
	if err := p.mounts(n, s, &c, uid, gid); err != nil {
		return err
	}
	p.containers = append(p.containers, c)
	return nil
}

// sizeQuantity maps docker's size units (1g, 64m, 512k) to a quantity.
func sizeQuantity(v string) string {
	v = strings.TrimSpace(v)
	for _, u := range []struct{ d, k string }{{"k", "Ki"}, {"m", "Mi"}, {"g", "Gi"}} {
		if s, ok := strings.CutSuffix(strings.ToLower(v), u.d); ok {
			return s + u.k
		}
	}
	return v
}

// containerName is a DNS label from a compose service name.
func containerName(n string) string {
	c := sanitize(n)
	if len(c) > maxName {
		sum := sha256.Sum256([]byte(n))
		c = strings.TrimRight(c[:maxName-9], "-") + "-" + hex.EncodeToString(sum[:])[:8]
	}
	return c
}

func (p *podSpec) mounts(n string, s types.ServiceConfig, c *corev1.Container, uid int64, gid *int64) error {
	t := p.t
	tplPrefix := "templates/" + t.in.Template + "/"
	for _, v := range s.Volumes {
		switch v.Type {
		case types.VolumeTypeTmpfs:
			ed := &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}
			if v.Tmpfs != nil && v.Tmpfs.Size > 0 {
				q := *resource.NewQuantity(int64(v.Tmpfs.Size), resource.BinarySI)
				ed.SizeLimit = &q
			}
			vn := fmt.Sprintf("tmpfs-%s-%s", containerName(n), shortHash(v.Target))
			p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{EmptyDir: ed}})
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: v.Target})
		case types.VolumeTypeVolume:
			if v.Source == "" {
				vn := "anon-" + containerName(n) + "-" + shortHash(v.Target)
				p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
				c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: v.Target, ReadOnly: v.ReadOnly})
				continue
			}
			if v.Source == templates.SecretsVolumeKey {
				if err := p.personSecret(n, v, c); err != nil {
					return err
				}
				continue
			}
			if err := p.pvc(n, v, c, uid, gid); err != nil {
				return err
			}
		case types.VolumeTypeBind:
			if err := p.bind(n, v, c, tplPrefix); err != nil {
				return err
			}
		default:
			return refused("service %s mounts a %s volume (not on Kubernetes)", n, v.Type)
		}
	}
	return nil
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

func (p *podSpec) personSecret(n string, v types.ServiceVolumeConfig, c *corev1.Container) error {
	t := p.t
	sub := ""
	if v.Volume != nil {
		sub = v.Volume.Subpath
	}
	inst, key, ok := strings.Cut(sub, "/")
	if !ok || inst != t.in.Instance || key == "" {
		return refused("service %s mounts the per-person secrets at %q, not its own", n, sub)
	}
	name := PersonSecretName(t.in.Instance, key)
	if !t.done["secret/"+name] {
		if err := t.claim("secret", name, "the per-person secrets "+key); err != nil {
			return err
		}
		data := map[string][]byte{}
		total := 0
		for f, b := range t.in.PersonSecrets[key] {
			data[sanitizeKey(f)] = b
			total += len(f) + len(b)
		}
		if total > MaxObject-16<<10 {
			return refused("secret %s exceeds 1 MiB", name)
		}
		if err := t.addShared(&corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta(name, t.in.Namespace, t.labels("")), Type: corev1.SecretTypeOpaque, Data: data}); err != nil {
			return err
		}
		t.done["secret/"+name] = true
	}
	mode := int32(0o440)
	vn := "pw-" + sanitize(key)
	p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: name, DefaultMode: &mode}}})
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: v.Target, ReadOnly: true})
	p.needBin = true
	return nil
}

func (p *podSpec) pvc(n string, v types.ServiceVolumeConfig, c *corev1.Container, uid int64, gid *int64) error {
	t := p.t
	if uid < 1 {
		return refused("service %s mounts volume %s without a numeric user: the volume's owner on Kubernetes is the service's uid", n, v.Source)
	}
	g := uid
	if gid != nil {
		g = *gid
	}
	name := PVCName(t.in.Instance, v.Source)
	if !t.done["pvc/"+name] {
		if err := t.claim("pvc", name, "volume "+v.Source); err != nil {
			return err
		}
		ann := map[string]string{AnnotationUID: strconv.FormatInt(uid, 10), AnnotationGID: strconv.FormatInt(g, 10), AnnotationMode: "0750"}
		sc := StorageClassApps
		pvc := &corev1.PersistentVolumeClaim{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: t.in.Namespace, Labels: map[string]string{LabelInstance: t.in.Instance, LabelVolume: sanitizeLabel(v.Source)}, Annotations: ann},
			Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: &sc,
				Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}}}}
		if err := t.addShared(pvc); err != nil {
			return err
		}
		t.done["pvc/"+name] = true
	}
	vn := "vol-" + sanitize(v.Source)
	if len(vn) > maxName {
		vn = "vol-" + shortHash(v.Source)
	}
	p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: name}}})
	m := corev1.VolumeMount{Name: vn, MountPath: v.Target, ReadOnly: v.ReadOnly}
	if v.Volume != nil && v.Volume.Subpath != "" {
		m.SubPath = v.Volume.Subpath
	}
	c.VolumeMounts = append(c.VolumeMounts, m)
	// K4: seed the PVC from the image's directory, as Docker's copy-up.
	if v.Volume == nil || !v.Volume.NoCopy {
		p.needBin = true
		p.seeds++
		seed := corev1.Container{
			Name:            fmt.Sprintf("portcullis-seed-%d", p.seeds),
			Image:           c.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"/portcullis-bin/hub", "seed", v.Target, "/portcullis-seed"},
			SecurityContext: seedContext(c.SecurityContext),
			VolumeMounts: []corev1.VolumeMount{
				{Name: "portcullis-bin", MountPath: "/portcullis-bin", ReadOnly: true},
				{Name: vn, MountPath: "/portcullis-seed", SubPath: m.SubPath},
			},
		}
		p.inits = append(p.inits, seed)
	}
	return nil
}

// seedContext is the seed init container's security context: the
// service's user, nothing added, no escalation, read-only root.
func seedContext(sc *corev1.SecurityContext) *corev1.SecurityContext {
	f, ro := false, true
	out := &corev1.SecurityContext{AllowPrivilegeEscalation: &f, ReadOnlyRootFilesystem: &ro, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}
	if sc != nil {
		out.RunAsUser, out.RunAsGroup = sc.RunAsUser, sc.RunAsGroup
	}
	return out
}

func (p *podSpec) bind(n string, v types.ServiceVolumeConfig, c *corev1.Container, tplPrefix string) error {
	t := p.t
	src := v.Source
	if af, ok := t.in.AppFiles[src]; ok {
		return p.appFile(n, af, v, c)
	}
	rel := strings.TrimPrefix(path.Clean(src), "./")
	if strings.HasPrefix(rel, tplPrefix) || rel+"/" == tplPrefix {
		return p.templateBind(n, strings.TrimPrefix(rel+"/", tplPrefix), v, c)
	}
	if path.IsAbs(src) && underAny(src, t.in.BindRoots) {
		dir := corev1.HostPathDirectory
		vn := "host-" + shortHash(src)
		p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path.Clean(src), Type: &dir}}})
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: v.Target, ReadOnly: v.ReadOnly})
		return nil
	}
	shown := src
	if !path.IsAbs(src) || strings.ContainsAny(src, " \t\n") {
		shown = "a host path"
	}
	return refused("service %s binds %s, outside the shared-folder roots (not on Kubernetes)", n, shown)
}

func underAny(p string, roots []string) bool {
	p = path.Clean(p)
	for _, r := range roots {
		r = path.Clean(r)
		if r != "/" && r != "." && (p == r || strings.HasPrefix(p, r+"/")) {
			return true
		}
	}
	return false
}

// templateBind mounts template files (a file or a directory below the
// template directory) from the template ConfigMap.
func (p *podSpec) templateBind(n, rel string, v types.ServiceVolumeConfig, c *corev1.Container) error {
	t := p.t
	rel = strings.TrimSuffix(rel, "/")
	if t.tplCM == "" {
		return refused("service %s binds template file %s, which doesn't exist", n, rel)
	}
	if k, ok := t.tplItems[rel]; ok {
		vn := "tpl-" + shortHash(rel)
		p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: t.tplCM}, Items: []corev1.KeyToPath{{Key: k, Path: path.Base(rel)}}}}})
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: v.Target, SubPath: path.Base(rel), ReadOnly: true})
		return nil
	}
	var items []corev1.KeyToPath
	prefix := rel + "/"
	if rel == "" {
		prefix = ""
	}
	for _, f := range slices.Sorted(mapKeys(t.tplItems)) {
		if r, ok := strings.CutPrefix(f, prefix); ok {
			items = append(items, corev1.KeyToPath{Key: t.tplItems[f], Path: r})
		}
	}
	if len(items) == 0 {
		return refused("service %s binds template file %s, which doesn't exist", n, rel)
	}
	vn := "tpl-" + shortHash(rel+"/")
	p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
		LocalObjectReference: corev1.LocalObjectReference{Name: t.tplCM}, Items: items}}})
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: v.Target, ReadOnly: true})
	return nil
}

// appFile mounts a data file (ConfigMap) and its secrets file (Secret)
// read-only at the bind's target directory, 0440 with the pod's fsGroup
// the service's gid, and the delivery revision as .rev (§13.7 "On
// Kubernetes"; one projected volume: the kubelet updates it atomically).
func (p *podSpec) appFile(n string, af AppFile, v types.ServiceVolumeConfig, c *corev1.Container) error {
	t := p.t
	if af.FileName == "" {
		af.FileName = af.Name + ".json"
	}
	cm := DataFileName(t.in.Instance, af.Name)
	if !t.done["configmap/"+cm] {
		if err := t.claim("configmap", cm, "data file "+af.Name); err != nil {
			return err
		}
		if len(af.Data) > MaxObject-16<<10 || len(af.Secrets) > MaxObject-16<<10 {
			return refused("data file %s exceeds 1 MiB", af.Name)
		}
		if err := t.addShared(&corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta(cm, t.in.Namespace, t.labels("")),
			BinaryData: map[string][]byte{af.FileName: af.Data}, Data: map[string]string{".rev": af.Rev}}); err != nil {
			return err
		}
		if af.Secrets != nil {
			sn := DataSecretsName(t.in.Instance, af.Name)
			if err := t.claim("secret", sn, "data file secrets "+af.Name); err != nil {
				return err
			}
			if err := t.addShared(&corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta(sn, t.in.Namespace, t.labels("")),
				Type: corev1.SecretTypeOpaque, Data: map[string][]byte{af.Name + ".secrets.json": af.Secrets}}); err != nil {
				return err
			}
		}
		t.done["configmap/"+cm] = true
	}
	dataMode, secMode := int32(0o440), int32(0o440)
	sources := []corev1.VolumeProjection{{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: cm},
		Items: []corev1.KeyToPath{{Key: af.FileName, Path: af.FileName, Mode: &dataMode}, {Key: ".rev", Path: ".rev", Mode: &dataMode}}}}}
	if af.Secrets != nil {
		sources = append(sources, corev1.VolumeProjection{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: DataSecretsName(t.in.Instance, af.Name)},
			Items: []corev1.KeyToPath{{Key: af.Name + ".secrets.json", Path: af.Name + ".secrets.json", Mode: &secMode}}}})
	}
	vn := "data-" + shortHash(af.Name)
	p.addVolume(corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: sources}}})
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: vn, MountPath: v.Target, ReadOnly: true})
	p.needBin = true
	return nil
}

func (p *podSpec) finish() corev1.PodSpec {
	t := p.t
	f := false
	spec := corev1.PodSpec{
		AutomountServiceAccountToken:  &f,
		EnableServiceLinks:            &f,
		SecurityContext:               p.sc,
		Containers:                    p.containers,
		TerminationGracePeriodSeconds: p.grace,
	}
	if p.needBin {
		ro, esc := true, false
		bin := corev1.Container{
			Name:            "portcullis-bin",
			Image:           t.in.HubImage,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"/usr/local/bin/hub", "seed", "/usr/local/bin", "/portcullis-bin"},
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &esc, ReadOnlyRootFilesystem: &ro, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "portcullis-bin", MountPath: "/portcullis-bin"}},
		}
		if len(p.containers) > 0 && p.containers[0].SecurityContext != nil {
			bin.SecurityContext.RunAsUser = p.containers[0].SecurityContext.RunAsUser
			bin.SecurityContext.RunAsGroup = p.containers[0].SecurityContext.RunAsGroup
		}
		spec.InitContainers = append([]corev1.Container{bin}, p.inits...)
		p.addVolume(corev1.Volume{Name: "portcullis-bin", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		for i := range spec.Containers {
			spec.Containers[i].VolumeMounts = append(spec.Containers[i].VolumeMounts, corev1.VolumeMount{Name: "portcullis-bin", MountPath: "/portcullis-bin", ReadOnly: true})
		}
	}
	sort.SliceStable(p.volumes, func(i, j int) bool { return p.volumes[i].Name < p.volumes[j].Name })
	spec.Volumes = p.volumes
	return spec
}

// servicePorts are the LoadBalancer Services of a pod's published ports
// (one per published port; lan_only → the Local networks as source
// ranges, no Service at all without any).
func (t *translator) servicePorts(pod string, members []string) ([]*unstructured.Unstructured, error) {
	var out []*unstructured.Unstructured
	for _, n := range members {
		for _, sp := range t.in.Model.Services[n].Ports {
			pub, err := strconv.Atoi(sp.Published)
			if err != nil || pub <= 0 {
				continue
			}
			proto := corev1.ProtocolTCP
			if strings.EqualFold(sp.Protocol, "udp") {
				proto = corev1.ProtocolUDP
			}
			name := joinName(t.in.Instance, fmt.Sprintf("%s-%d-%s", pod, pub, strings.ToLower(string(proto))), "")
			if err := t.claim("service", name, fmt.Sprintf("port %d/%s of %s", pub, proto, n)); err != nil {
				return nil, err
			}
			f := false
			svc := &corev1.Service{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: meta(name, t.in.Namespace, t.labels(pod)),
				Spec: corev1.ServiceSpec{
					Type:                          corev1.ServiceTypeLoadBalancer,
					ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyLocal,
					AllocateLoadBalancerNodePorts: &f,
					Selector:                      t.labels(pod),
					Ports:                         []corev1.ServicePort{{Name: strings.ToLower(string(proto)) + "-" + strconv.Itoa(pub), Port: int32(pub), TargetPort: intstr.FromInt32(int32(sp.Target)), Protocol: proto}},
				}}
			if t.in.LanOnly[pub] {
				var ranges []string
				for _, r := range t.in.Settings.LocalNetworks {
					if !strings.Contains(r, ":") {
						ranges = append(ranges, r)
					}
				}
				if len(ranges) == 0 {
					continue // no Local networks: not reachable at all
				}
				svc.Spec.LoadBalancerSourceRanges = ranges
			}
			u, err := toUnstructured(svc)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
	}
	return out, nil
}

// sanitizeLabel is s as a label value (≤ 63, alphanumerics, "-", "_",
// "."; starting and ending alphanumeric).
func sanitizeLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
	if len(s) > maxName {
		s = s[:maxName]
	}
	return strings.Trim(s, "-_.")
}
