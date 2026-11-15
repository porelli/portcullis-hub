package agentapi

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/templates"
)

// ProjectLabel is compose's project label; a bundled instance's project
// is runtime.ProjectName(id).
const ProjectLabel = "com.docker.compose.project"

// ValidInstance: an instance id as the contract allows (§11.1: the
// template id pattern in its normal form, no "portcullis" segment, no
// "--").
func ValidInstance(id string) error {
	if !templates.ValidID(id) {
		return fmt.Errorf("instance %q is not an instance id", clip(id))
	}
	if err := templates.CheckIDShape(id); err != nil {
		return fmt.Errorf("instance %q is not an instance id", clip(id))
	}
	return nil
}

// ProjectLabelOK: labels name a bundled project (com.docker.compose.project
// = portcullis-<id>, id a valid instance id in bundled). It returns the id
// and whether the container (or volume) is in the agent's scope; anything
// else (core's project "portcullis", no label, another project) is out.
func ProjectLabelOK(labels map[string]string, bundled map[string]bool) (string, bool) {
	p, ok := labels[ProjectLabel]
	if !ok {
		return "", false
	}
	id, ok := strings.CutPrefix(p, runtime.ProjectPrefix)
	if !ok || ValidInstance(id) != nil || !bundled[id] {
		return "", false
	}
	return id, true
}

// workerNames are the worker stack's service names (core's
// docker-compose.worker.yml): DNS names a template may not answer to on a
// worker either.
var workerNames = map[string]bool{"agent": true, "socket-proxy-agent": true}

func reservedName(n string) bool {
	f := strings.TrimSuffix(templates.FoldKey(strings.TrimSpace(n)), ".")
	first, _, _ := strings.Cut(f, ".")
	return templates.ReservedDNSName(n) || workerNames[f] || workerNames[first]
}

func bundleError(format string, args ...any) error {
	return fmt.Errorf("bundle refused: "+format, args...)
}

// ── Allowlists (contract §17.4: a worker runs only what these name; any
// other compose key, present or future, is refused by default) ──────────

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

var (
	// serviceKeys a bundle's service may set (the templates' allowed keys
	// as the real templates and the Hub's overrides use them; each one
	// with a value rule below where it matters). Not here, so refused:
	// hooks (pre_start, post_start, pre_stop), provider, models, develop,
	// deploy, build, extends, privileged, use_api_socket, gpus, sysctls,
	// userns_mode, uts, cgroup, cgroup_parent, runtime, isolation,
	// credential_spec, label_file, annotations, env_file, configs,
	// mac_address (a service-level MAC lands on portcullis-proxy, where
	// fixed addresses are refused; no template sets one),
	// secrets, external_links, net, volume_driver, storage_opt,
	// blkio_config, device_cgroup_rules, oom_kill_disable, the cpu_*
	// scheduler knobs, and service-level x-* extensions.
	serviceKeys = set("name", "profiles", "restart", "scale", "attach", "container_name", "links",
		"cap_add", "cap_drop", "cpus", "cpu_shares", "cpuset", "command", "devices", "dns", "dns_opt", "dns_search",
		"domainname", "entrypoint", "environment", "extra_hosts", "group_add", "hostname", "image", "init", "ipc",
		"labels", "logging", "mem_limit", "mem_reservation", "memswap_limit", "mem_swappiness",
		"network_mode", "networks", "oom_score_adj", "pid", "pids_limit", "platform", "pull_policy", "read_only",
		"security_opt", "shm_size", "stop_grace_period", "stop_signal", "tmpfs", "ulimits", "user", "volumes",
		"volumes_from", "working_dir",
		"depends_on", "expose", "healthcheck", "ports", "stdin_open", "tty")
	serviceNetworkKeys = set("aliases", "ipv4_address", "ipv6_address", "priority", "gw_priority")
	mountKeys          = set("type", "source", "target", "read_only", "consistency", "bind", "volume", "tmpfs")
	bindKeys           = set("propagation", "create_host_path", "selinux", "recursive")
	mountVolumeKeys    = set("nocopy", "subpath")
	mountTmpfsKeys     = set("size", "mode")
	networkKeys        = set("name", "driver", "external", "internal", "attachable", "labels", "enable_ipv4", "enable_ipv6")
	volumeKeys         = set("name", "driver", "labels")
	loggingDrivers     = set("", "json-file", "local")
)

// checkKeys refuses every field of struct v (inline structs flattened)
// that holds a value and whose yaml key isn't in allowed. Fields compose
// fills itself (yaml "-") are skipped.
func checkKeys(v reflect.Value, allowed map[string]bool, what string) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("yaml")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" && strings.Contains(opts, "inline") && f.Type.Kind() == reflect.Struct {
			if err := checkKeys(v.Field(i), allowed, what); err != nil {
				return err
			}
			continue
		}
		if v.Field(i).IsZero() {
			continue
		}
		if name == "#extensions" {
			return fmt.Errorf("%s: x-* extension keys are not allowed in a worker bundle", what)
		}
		if !allowed[name] {
			return fmt.Errorf("%s: compose key %s is not allowed in a worker bundle", what, name)
		}
	}
	return nil
}

// ── Volume names (contract §11.2), from the Hub's manifest ──────────────

var volumeKeyRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// ownVolumePrefixes are the prefixes an instance's own volume names
// start with (the longest match decides ownership against another
// instance's).
func ownVolumePrefixes(instance string) []string {
	return []string{runtime.ProjectName(instance) + "_", "portcullis_" + instance + "-", "portcullis_" + instance + "_"}
}

// volumeNameOK: name is one of the names the instance's key may have
// (§11.2): compose's portcullis-<id>_<key>; a multi template's
// portcullis_<id>-<key>; for the template's default instance only, a
// multi template's portcullis_<key> or a single template's declared
// portcullis_<id>[-_…]. Never a core volume's name.
func volumeNameOK(m BundleManifest, key, name string) bool {
	if templates.CoreVolumeName(name) != "" {
		return false
	}
	inst := m.Instance
	if name == runtime.ProjectName(inst)+"_"+key || name == "portcullis_"+inst+"-"+key {
		return true
	}
	if m.Template != inst {
		return false
	}
	own := "portcullis_" + inst
	return name == "portcullis_"+key || name == own || strings.HasPrefix(name, own+"-") || strings.HasPrefix(name, own+"_")
}

// ownPrefixLen is the length of the longest own prefix name starts with
// (len("portcullis_") for a default instance's portcullis_<key>).
func ownPrefixLen(instance, name string) int {
	n := 0
	if name == "portcullis_"+instance {
		n = len(name)
	}
	for _, p := range ownVolumePrefixes(instance) {
		if strings.HasPrefix(name, p) && len(p) > n {
			n = len(p)
		}
	}
	if n == 0 && strings.HasPrefix(name, "portcullis_") {
		n = len("portcullis_")
	}
	return n
}

// checkVolumeNames: m's volume names are the instance's own and none is
// (or falls under) another bundled instance's: equal to a name another
// manifest lists, or under another instance's prefix at least as long as
// the instance's own matching prefix (instance photos may not name
// portcullis_photos-2-…, which photos-2 owns; photos-2 may).
func checkVolumeNames(m BundleManifest, others []BundleManifest) error {
	taken := map[string]string{}
	for _, o := range others {
		if o.Instance == m.Instance {
			continue
		}
		for _, n := range o.Volumes {
			taken[n] = o.Instance
		}
	}
	for _, k := range sortedKeys(m.Volumes) {
		name := m.Volumes[k]
		if inst, ok := taken[name]; ok {
			return fmt.Errorf("volume %s: %s is instance %s's", clip(k), clip(name), inst)
		}
		own := ownPrefixLen(m.Instance, name)
		for _, o := range others {
			if o.Instance == m.Instance {
				continue
			}
			pre := ownVolumePrefixes(o.Instance)
			if name == "portcullis_"+o.Instance {
				pre = append(pre, name)
			}
			for _, p := range pre {
				if strings.HasPrefix(name, p) && len(p) >= own {
					return fmt.Errorf("volume %s: %s falls under instance %s's names", clip(k), clip(name), o.Instance)
				}
			}
		}
	}
	return nil
}

// ── ValidateBundle ──────────────────────────────────────────────────────

// ValidateBundle re-validates a bundle's loaded compose model (every
// profile; services and disabled services) before the agent runs it
// (pre-flight P4: the rules on the result, not on the override input).
// m is the bundle's manifest (the Hub's: the instance, its template and
// its volume names), others the manifests of the worker's other bundled
// instances, bindRoots the worker's folder roots (absolute, clean),
// bundleDir the bundle's directory (absolute; relative bind sources
// resolve there), readOnlyDirs directories binds may use read-only only
// (the instance's appfiles: a container can't plant a symlink there for
// the agent to write through).
//
// Everything is allowlisted: a compose key outside the lists above is
// refused, whatever it is. Then, refused:
//   - a project name other than portcullis-<instance>; jobs, models,
//     configs or secrets;
//   - networks: an external one other than portcullis-proxy, a name other
//     than <project>_<key>, a driver other than bridge, driver_opts or a
//     custom ipam;
//   - volumes: an external one, a driver other than local, driver_opts,
//     a core volume, a key the manifest doesn't name or a name other than
//     the manifest's, a name outside the instance's §11.2 names or under
//     another bundled instance's (checkVolumeNames);
//   - per service: devices other than /dev/null slots, cap_add outside
//     Docker's default set (templates.KubeBaselineCaps), security_opt
//     other than no-new-privileges, network_mode other than none /
//     service:<own>, pid / ipc sharing with the host or a container,
//     extra_hosts host-gateway, pull_policy build, a logging driver other
//     than json-file or local, links / volumes_from other than an own
//     service, com.docker.compose.* labels, a reserved DNS name (core's or
//     the worker stack's), a network the model doesn't declare, a fixed
//     address on portcullis-proxy (the agent's own address there is the
//     Traefik IP);
//   - per mount: a volume source the model doesn't declare (or a core
//     volume), a bind source with "..", "~", a socket (*.sock), the host's
//     root, outside bundleDir and every root, propagation shared/slave,
//     any type but bind, volume or tmpfs.
//
// BundleScope is where a bundle's binds may point (contract §17.4):
//   - BindRoots: the worker's folder roots (a bind under one, read-write
//     allowed; the root itself only when no protected path is in it);
//   - ReadOnlyDirs: the instance's own files and appfiles directories
//     (binds must be read-only; SELinux "z" allowed there only);
//   - Protected: never bound — a bind equal to one, an ancestor of one or
//     inside one is refused ("/" itself: equal only): the agent's data
//     dir, the projects root, the engine's roots and sockets, "/";
//   - ProjectDir: the directory of the compose files: no bind equals,
//     contains or is inside it;
//   - BaseDir: relative sources resolve here ("" = a relative source is
//     refused: the agent validates compose config's absolute model).
type BundleScope struct {
	BindRoots, ReadOnlyDirs, Protected []string
	ProjectDir, BaseDir                string
}

func cleanAbs(list []string, what string) ([]string, error) {
	var out []string
	for _, r := range list {
		if !path.IsAbs(r) || path.Clean(r) != r {
			return nil, fmt.Errorf("%s %q must be an absolute clean path", what, clip(r))
		}
		out = append(out, r)
	}
	return out, nil
}

func ValidateBundle(model *types.Project, m BundleManifest, others []BundleManifest, scope BundleScope) error {
	if model == nil {
		return bundleError("no compose model")
	}
	if err := validateIdentity(m); err != nil {
		return bundleError("%v", err)
	}
	instance := m.Instance
	for _, l := range [][]string{scope.BindRoots, scope.ReadOnlyDirs} {
		for _, r := range l {
			if r == "/" {
				return bundleError("the host's root can't be a folder root or a bundle directory")
			}
		}
	}
	var err error
	sc := scope
	if sc.BindRoots, err = cleanAbs(scope.BindRoots, "folder root"); err != nil {
		return bundleError("%v", err)
	}
	if sc.ReadOnlyDirs, err = cleanAbs(scope.ReadOnlyDirs, "directory"); err != nil {
		return bundleError("%v", err)
	}
	if sc.Protected, err = cleanAbs(append(append([]string{}, scope.Protected...), "/"), "protected path"); err != nil {
		return bundleError("%v", err)
	}
	for _, d := range []string{scope.ProjectDir, scope.BaseDir} {
		if d != "" && (!path.IsAbs(d) || path.Clean(d) != d || d == "/") {
			return bundleError("directory %q must be an absolute clean path other than /", clip(d))
		}
	}
	project := runtime.ProjectName(instance)
	if model.Name != project {
		return bundleError("project %q is not %s", clip(model.Name), project)
	}
	switch {
	case len(model.Jobs) > 0 || len(model.DisabledJobs) > 0:
		return bundleError("compose jobs are not allowed in a worker bundle")
	case len(model.Models) > 0:
		return bundleError("compose models are not allowed in a worker bundle")
	case len(model.Configs) > 0 || len(model.Secrets) > 0:
		return bundleError("configs and secrets read files the Hub can't check")
	}
	if err := checkVolumeNames(m, others); err != nil {
		return bundleError("%v", err)
	}
	for _, k := range sortedKeys(model.Networks) {
		n := model.Networks[k]
		what := "network " + clip(k)
		if err := checkKeys(reflect.ValueOf(n), networkKeys, what); err != nil {
			return bundleError("%v", err)
		}
		if k := reservedLabel(n.Labels); k != "" {
			return bundleError("%s: label %s is compose's or Portcullis's own", what, clip(k))
		}
		if bool(n.External) {
			if n.Name != "portcullis-proxy" {
				return bundleError("%s: only portcullis-proxy may be external", what)
			}
			continue
		}
		if n.Name != project+"_"+k {
			return bundleError("%s: named %q, not the project's own %s_%s", what, clip(n.Name), project, clip(k))
		}
		if n.Driver != "" && n.Driver != "bridge" {
			return bundleError("%s: driver %q: only bridge", what, clip(n.Driver))
		}
	}
	for _, k := range sortedKeys(model.Volumes) {
		v := model.Volumes[k]
		what := "volume " + clip(k)
		if c := templates.CoreVolumeName(k); c != "" {
			return bundleError("%s is core's (%s)", what, c)
		}
		if bool(v.External) {
			return bundleError("%s: external volumes are another project's data", what)
		}
		if k := reservedLabel(v.Labels); k != "" {
			return bundleError("%s: label %s is compose's or Portcullis's own", what, clip(k))
		}
		if err := checkKeys(reflect.ValueOf(v), volumeKeys, what); err != nil {
			return bundleError("%v (a local driver_opts device is a bind)", err)
		}
		if v.Driver != "" && v.Driver != "local" {
			return bundleError("%s: only the local driver", what)
		}
		if c := templates.CoreVolumeName(v.Name); c != "" {
			return bundleError("%s is named %s, core's volume", what, clip(v.Name))
		}
		want, ok := m.Volumes[k]
		if !ok {
			return bundleError("%s is not in the bundle manifest", what)
		}
		if v.Name != want {
			return bundleError("%s: named %q, the manifest says %q", what, clip(v.Name), clip(want))
		}
	}
	all := map[string]types.ServiceConfig{}
	for n, s := range model.DisabledServices {
		all[n] = s
	}
	for n, s := range model.Services {
		all[n] = s
	}
	for _, n := range sortedKeys(all) {
		if err := checkService(n, all[n], all, model, sc); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func nsOK(v string, own map[string]types.ServiceConfig, allowed ...string) bool {
	if v == "" || slices.Contains(allowed, v) {
		return true
	}
	if t, ok := strings.CutPrefix(v, types.NetworkModeServicePrefix); ok {
		_, isOwn := own[t]
		return isOwn
	}
	return false
}

func checkService(n string, s types.ServiceConfig, own map[string]types.ServiceConfig, model *types.Project, sc BundleScope) error {
	what := "service " + clip(n)
	fail := func(format string, args ...any) error {
		return bundleError(what+": "+format, args...)
	}
	if err := checkKeys(reflect.ValueOf(s), serviceKeys, what); err != nil {
		return bundleError("%v", err)
	}
	switch {
	case !nsOK(s.Pid, own):
		return fail("pid %q shares another PID namespace", clip(s.Pid))
	case !nsOK(s.Ipc, own, "private", "shareable", "none"):
		return fail("ipc %q shares another IPC namespace", clip(s.Ipc))
	case !nsOK(s.NetworkMode, own, "none"):
		return fail("network_mode %q: only none or service:<own service>", clip(s.NetworkMode))
	case s.PullPolicy == types.PullPolicyBuild:
		return fail("pull_policy build: the agent never builds")
	case s.Logging != nil && !loggingDrivers[s.Logging.Driver]:
		return fail("logging driver %q: only json-file or local", clip(s.Logging.Driver))
	}
	for _, d := range s.Devices {
		if d.Source != "/dev/null" {
			return fail("passes the host device %s: host devices aren't allowed on a worker", clip(d.Source))
		}
	}
	for _, c := range s.CapAdd {
		cp := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
		if !slices.Contains(templates.KubeBaselineCaps, cp) {
			return fail("cap_add %s is outside the engine's default set", clip(cp))
		}
	}
	for _, o := range s.SecurityOpt {
		switch strings.ReplaceAll(strings.TrimSpace(o), "=", ":") {
		case "no-new-privileges", "no-new-privileges:true":
		default:
			return fail("security_opt %q: only no-new-privileges", clip(o))
		}
	}
	for host, ips := range s.ExtraHosts {
		for _, ip := range ips {
			if strings.EqualFold(strings.TrimSpace(ip), "host-gateway") {
				return fail("extra_hosts %s: host-gateway reaches the worker host", clip(host))
			}
		}
	}
	for _, vf := range s.VolumesFrom {
		src, _, _ := strings.Cut(vf, ":")
		if _, ok := own[src]; !ok || strings.HasPrefix(vf, "container:") {
			return fail("volumes_from %s is not a service of this project", clip(vf))
		}
	}
	for _, l := range s.Links {
		src, alias, _ := strings.Cut(l, ":")
		if _, ok := own[src]; !ok {
			return fail("links %s is not a service of this project", clip(l))
		}
		if alias != "" && reservedName(alias) {
			return fail("links alias %q is reserved", clip(alias))
		}
	}
	if k := reservedLabel(s.Labels); k != "" {
		return fail("label %s is compose's or Portcullis's own", clip(k))
	}
	// Resource bounds (review L6): no OOM preference over the host, and
	// bounded shared memory.
	if s.OomScoreAdj < 0 {
		return fail("oom_score_adj below 0 is not allowed on a worker")
	}
	if s.ShmSize > MaxShmSize {
		return fail("shm_size over %d bytes", int64(MaxShmSize))
	}
	for _, name := range []string{n, s.ContainerName, s.Hostname} {
		if name != "" && reservedName(name) {
			return fail("the DNS name %q is reserved", clip(name))
		}
	}
	for _, net := range sortedKeys(s.Networks) {
		decl, ok := model.Networks[net]
		if !ok {
			return fail("network %s is not declared", clip(net))
		}
		cfg := s.Networks[net]
		if cfg == nil {
			continue
		}
		if err := checkKeys(reflect.ValueOf(cfg), serviceNetworkKeys, what+": network "+clip(net)); err != nil {
			return bundleError("%v", err)
		}
		if bool(decl.External) && (cfg.Ipv4Address != "" || cfg.Ipv6Address != "") {
			return fail("network %s: a fixed address on a shared network (the agent holds the Traefik address there)", clip(net))
		}
		for _, a := range cfg.Aliases {
			if reservedName(a) {
				return fail("network alias %q is reserved", clip(a))
			}
		}
	}
	for _, mnt := range s.Volumes {
		if err := checkMount(mnt, model, sc); err != nil {
			return fail("%v", err)
		}
	}
	return nil
}

// reservedLabel is the first label key compose or Portcullis owns
// (com.docker.compose.*, io.portcullis.*: a container carrying the
// helper label would pass for the agent's own).
func reservedLabel(l map[string]string) string {
	for _, k := range sortedKeys(l) {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "com.docker.compose.") || strings.HasPrefix(lk, "io.portcullis.") || strings.HasPrefix(lk, "io.portcullis/") {
			return k
		}
	}
	return ""
}

// MaxShmSize / MaxTmpfsSize bound a service's shared memory and tmpfs.
const (
	MaxShmSize   = 2 << 30
	MaxTmpfsSize = 2 << 30
)

func checkMount(m types.ServiceVolumeConfig, model *types.Project, sc BundleScope) error {
	if err := checkKeys(reflect.ValueOf(m), mountKeys, "mount "+clip(m.Target)); err != nil {
		return err
	}
	for _, sub := range []struct {
		v       any
		allowed map[string]bool
	}{{m.Bind, bindKeys}, {m.Volume, mountVolumeKeys}, {m.Tmpfs, mountTmpfsKeys}} {
		if err := checkKeys(reflect.ValueOf(sub.v), sub.allowed, "mount "+clip(m.Target)); err != nil {
			return err
		}
	}
	switch m.Type {
	case types.VolumeTypeTmpfs:
		if m.Tmpfs != nil && (m.Tmpfs.Size < 0 || int64(m.Tmpfs.Size) > MaxTmpfsSize) {
			return fmt.Errorf("tmpfs %s: size over %d bytes", clip(m.Target), int64(MaxTmpfsSize))
		}
		return nil
	case types.VolumeTypeVolume:
		if m.Source == "" {
			return nil // anonymous
		}
		if c := templates.CoreVolumeName(m.Source); c != "" {
			return fmt.Errorf("mounts the core volume %s", c)
		}
		if _, ok := model.Volumes[m.Source]; !ok {
			return fmt.Errorf("volume %s is not declared", clip(m.Source))
		}
		return nil
	case types.VolumeTypeBind:
	default:
		return fmt.Errorf("mount type %q: only bind, volume or tmpfs", clip(m.Type))
	}
	src := m.Source
	if m.Bind != nil {
		switch m.Bind.Propagation {
		case "", "private", "rprivate":
		default:
			return fmt.Errorf("bind %s: propagation %q is not allowed", clip(src), clip(m.Bind.Propagation))
		}
	}
	switch {
	case src == "":
		return errors.New("a bind mount without a source")
	case strings.HasPrefix(src, "~"):
		return fmt.Errorf("bind %s: ~ is the engine's home, not a bundle path", clip(src))
	case templates.HasDotDotSegment(src):
		return fmt.Errorf("bind %s: \"..\" segments are not allowed", clip(src))
	}
	p := src
	if !path.IsAbs(p) {
		if sc.BaseDir == "" {
			return fmt.Errorf("bind %s: a relative source", clip(src))
		}
		p = path.Join(sc.BaseDir, p)
	}
	p = path.Clean(p)
	if p == "/" {
		return fmt.Errorf("bind %s: the host's root directory", clip(src))
	}
	if strings.HasSuffix(p, ".sock") {
		return fmt.Errorf("bind %s: sockets are not allowed", clip(src))
	}
	selinux := m.Bind != nil && m.Bind.SELinux != ""
	if selinux && m.Bind.SELinux != "z" {
		return fmt.Errorf("bind %s: SELinux %q (a private relabel) is not allowed", clip(src), clip(m.Bind.SELinux))
	}
	if d := sc.ProjectDir; d != "" && (under(p, d) || under(d, p)) {
		return fmt.Errorf("bind %s: the compose files' directory is never bound", clip(src))
	}
	for _, r := range sc.ReadOnlyDirs {
		if under(p, r) {
			if !m.ReadOnly {
				return fmt.Errorf("bind %s must be read-only", clip(src))
			}
			return nil
		}
	}
	for _, f := range sc.Protected {
		if p == f || (f != "/" && (under(p, f) || under(f, p))) {
			return fmt.Errorf("a protected path (the agent's data, the engine's roots and sockets) is bound: %s (%s)", clip(src), clip(f))
		}
	}
	if selinux {
		return fmt.Errorf("bind %s: SELinux relabels are allowed only on the instance's own files", clip(src))
	}
	for _, r := range sc.BindRoots {
		if under(p, r) {
			return nil
		}
	}
	return fmt.Errorf("bind %s is outside the server's folder roots", clip(src))
}

func under(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }
