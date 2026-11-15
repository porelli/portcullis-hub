package agentapi

import (
	"errors"
	"fmt"
	"path"
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

// bundleError is one refusal.
func bundleError(format string, args ...any) error {
	return fmt.Errorf("bundle refused: "+format, args...)
}

// ValidateBundle re-validates a bundle's loaded compose model (every
// profile; services and disabled services) before the agent runs it
// (pre-flight P4: the rules on the result, not on the override input).
// instance is the bundle's id, bindRoots the worker's folder roots
// (absolute, clean), bundleDir the bundle's directory (absolute, the
// project directory; relative bind sources resolve there). Refused:
//   - a project name other than portcullis-<instance>;
//   - project-level configs, secrets or a network/volume that isn't the
//     project's own: an external network other than portcullis-proxy, a
//     network named other than <project>_<key>, any external volume, a
//     volume named outside the instance's names (<project>_<key>,
//     portcullis_<key>, portcullis_<instance>[-_…]), a core volume, a
//     volume driver other than local or with driver_opts;
//   - per service: build, privileged, devices other than /dev/null slots,
//     device_cgroup_rules, gpus, deploy device reservations, cap_add
//     outside Docker's default set (templates.KubeBaselineCaps),
//     security_opt other than no-new-privileges, network_mode other than
//     none / service:<own>, pid / ipc / uts / userns / cgroup sharing with
//     the host or a container, cgroup_parent, runtime, isolation,
//     sysctls, extra_hosts host-gateway, env_file, configs, secrets,
//     external_links, volumes_from other than an own service,
//     com.docker.compose.* labels, a reserved DNS name (core's or the
//     worker stack's), attachment to a network the model doesn't declare;
//   - per mount: a volume source the model doesn't declare (or a core
//     volume), a bind source with "..", "~", a socket (*.sock), the
//     host's root, outside bundleDir and every root, bind propagation
//     shared/slave, any type but bind, volume or tmpfs.
func ValidateBundle(model *types.Project, instance string, bindRoots []string, bundleDir string) error {
	if model == nil {
		return bundleError("no compose model")
	}
	if err := ValidInstance(instance); err != nil {
		return bundleError("%v", err)
	}
	if !path.IsAbs(bundleDir) || path.Clean(bundleDir) != bundleDir || bundleDir == "/" {
		return bundleError("the bundle directory must be an absolute clean path")
	}
	var roots []string
	for _, r := range bindRoots {
		if !path.IsAbs(r) || path.Clean(r) != r || r == "/" {
			return bundleError("folder root %q must be an absolute clean path other than /", clip(r))
		}
		roots = append(roots, r)
	}
	project := runtime.ProjectName(instance)
	if model.Name != project {
		return bundleError("project %q is not %s", clip(model.Name), project)
	}
	if len(model.Configs) > 0 || len(model.Secrets) > 0 {
		return bundleError("configs and secrets read files the Hub can't check")
	}
	for _, k := range sortedKeys(model.Networks) {
		n := model.Networks[k]
		if bool(n.External) {
			if n.Name != "portcullis-proxy" {
				return bundleError("network %s: only portcullis-proxy may be external", clip(k))
			}
			continue
		}
		if n.Name != project+"_"+k {
			return bundleError("network %s: named %q, not the project's own %s_%s", clip(k), clip(n.Name), project, clip(k))
		}
	}
	for _, k := range sortedKeys(model.Volumes) {
		v := model.Volumes[k]
		if c := templates.CoreVolumeName(k); c != "" {
			return bundleError("volume %s is core's (%s)", clip(k), c)
		}
		if bool(v.External) {
			return bundleError("volume %s: external volumes are another project's data", clip(k))
		}
		if c := templates.CoreVolumeName(v.Name); c != "" {
			return bundleError("volume %s is named %s, core's volume", clip(k), clip(v.Name))
		}
		if !ownVolumeName(v.Name, k, instance) {
			return bundleError("volume %s: named %q, outside the instance's names", clip(k), clip(v.Name))
		}
		if (v.Driver != "" && v.Driver != "local") || len(v.DriverOpts) > 0 {
			return bundleError("volume %s: only the local driver without driver_opts (a driver_opts device is a bind)", clip(k))
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
		if err := checkService(n, all[n], all, model, roots, bundleDir); err != nil {
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

// ownVolumeName: the names an instance's volume may have (contract §11.2:
// compose's <project>_<key>, a multi template's portcullis_<key> (default
// instance) or portcullis_<id>-<key>, a single template's declared
// portcullis_<id>[-_…]).
func ownVolumeName(name, key, instance string) bool {
	own := "portcullis_" + instance
	return name == runtime.ProjectName(instance)+"_"+key || name == "portcullis_"+key ||
		name == own || strings.HasPrefix(name, own+"-") || strings.HasPrefix(name, own+"_")
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

func checkService(n string, s types.ServiceConfig, own map[string]types.ServiceConfig, model *types.Project, roots []string, bundleDir string) error {
	fail := func(format string, args ...any) error {
		return bundleError("service %s: "+format, append([]any{clip(n)}, args...)...)
	}
	switch {
	case s.Build != nil:
		return fail("build is not allowed (the agent never builds)")
	case s.Privileged:
		return fail("privileged containers can take over the host")
	case len(s.DeviceCgroupRules) > 0:
		return fail("device_cgroup_rules grant host devices")
	case len(s.Gpus) > 0:
		return fail("gpus grant host devices")
	case len(s.Sysctls) > 0:
		return fail("sysctls are not allowed on a worker")
	case len(s.EnvFiles) > 0:
		return fail("env_file reads files the Hub can't check")
	case len(s.Configs) > 0 || len(s.Secrets) > 0:
		return fail("configs and secrets read files the Hub can't check")
	case len(s.ExternalLinks) > 0:
		return fail("external_links attach other containers")
	case s.CgroupParent != "":
		return fail("cgroup_parent moves the container out of the engine's cgroup")
	case s.Runtime != "":
		return fail("runtime changes the container's isolation")
	case s.Isolation != "" && s.Isolation != "default":
		return fail("isolation changes the container's isolation")
	case s.UserNSMode != "":
		return fail("userns_mode can disable user-namespace remapping")
	case s.Uts != "":
		return fail("uts shares the host's UTS namespace")
	case s.Cgroup != "" && s.Cgroup != "private":
		return fail("cgroup %q shares the host's cgroup namespace", clip(s.Cgroup))
	case !nsOK(s.Pid, own):
		return fail("pid %q shares another PID namespace", clip(s.Pid))
	case !nsOK(s.Ipc, own, "private", "shareable", "none"):
		return fail("ipc %q shares another IPC namespace", clip(s.Ipc))
	case !nsOK(s.NetworkMode, own, "none"):
		return fail("network_mode %q: only none or service:<own service>", clip(s.NetworkMode))
	}
	if s.Deploy != nil && s.Deploy.Resources.Reservations != nil && len(s.Deploy.Resources.Reservations.Devices) > 0 {
		return fail("deploy device reservations grant host devices")
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
		if strings.HasPrefix(vf, "container:") {
			return fail("volumes_from %s mounts another container's volumes", clip(vf))
		}
		if _, ok := own[src]; !ok {
			return fail("volumes_from %s is not a service of this project", clip(vf))
		}
	}
	for _, k := range sortedKeys(s.Labels) {
		if strings.HasPrefix(strings.ToLower(k), "com.docker.compose.") {
			return fail("label %s is compose's own", clip(k))
		}
	}
	for _, name := range []string{n, s.ContainerName, s.Hostname} {
		if name != "" && reservedName(name) {
			return fail("the DNS name %q is reserved", clip(name))
		}
	}
	for _, net := range sortedKeys(s.Networks) {
		if _, ok := model.Networks[net]; !ok {
			return fail("network %s is not declared", clip(net))
		}
		if cfg := s.Networks[net]; cfg != nil {
			for _, a := range cfg.Aliases {
				if reservedName(a) {
					return fail("network alias %q is reserved", clip(a))
				}
			}
		}
	}
	for _, m := range s.Volumes {
		if err := checkMount(m, model, roots, bundleDir); err != nil {
			return fail("%v", err)
		}
	}
	return nil
}

func checkMount(m types.ServiceVolumeConfig, model *types.Project, roots []string, bundleDir string) error {
	switch m.Type {
	case types.VolumeTypeTmpfs:
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
		p = path.Join(bundleDir, p)
	}
	p = path.Clean(p)
	if p == "/" {
		return fmt.Errorf("bind %s: the host's root directory", clip(src))
	}
	if strings.HasSuffix(p, ".sock") {
		return fmt.Errorf("bind %s: sockets are not allowed", clip(src))
	}
	if under(p, bundleDir) {
		return nil
	}
	for _, r := range roots {
		if under(p, r) {
			return nil
		}
	}
	return fmt.Errorf("bind %s is outside the bundle and the server's folder roots", clip(src))
}

func under(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }
