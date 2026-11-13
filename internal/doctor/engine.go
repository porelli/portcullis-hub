package doctor

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Rootless Podman (contract §14.5): five kinds that run only under
// HUB_CONTAINER_RUNTIME=podman (Inputs.Engine.Runtime "podman"; under
// Docker, or without engine inputs, they never fire). All explain-only.
const (
	KindRuntimeMismatch     = "runtime_mismatch"
	KindLimitsNotEnforced   = "limits_not_enforced"
	KindUnmappedOwner       = "unmapped_owner"
	KindSELinuxLabelMissing = "selinux_label_missing"
	KindUDPSourceRewritten  = "udp_source_rewritten"
)

// EngineKinds are the rootless Podman kinds.
var EngineKinds = []string{KindRuntimeMismatch, KindLimitsNotEnforced, KindUnmappedOwner, KindSELinuxLabelMissing, KindUDPSourceRewritten}

// EngineIn is the container engine as the Hub's start-time check saw it
// (contract §6): the configured runtime, the contradiction's text ("" =
// none) and whether the engine's SecurityOptions carry name=selinux.
type EngineIn struct {
	Runtime  string
	Mismatch string
	SELinux  bool
}

// selinuxContainerType is the label type rootless containers may read.
const selinuxContainerType = "container_file_t"

func init() {
	for _, k := range EngineKinds {
		Register(engineCheck{kind: k})
	}
}

type engineCheck struct{ kind string }

func (c engineCheck) Kind() string { return c.kind }

func (c engineCheck) Run(in *Inputs) []Finding {
	if in.Engine == nil || in.Engine.Runtime != "podman" {
		return nil
	}
	switch c.kind {
	case KindRuntimeMismatch:
		return runtimeMismatch(in)
	case KindLimitsNotEnforced:
		return limitsNotEnforced(in)
	case KindUnmappedOwner:
		return unmappedOwners(in)
	case KindSELinuxLabelMissing:
		return selinuxLabelMissing(in)
	case KindUDPSourceRewritten:
		return udpSourceRewritten(in)
	}
	return nil
}

func runtimeMismatch(in *Inputs) []Finding {
	if in.Engine.Mismatch == "" {
		return nil
	}
	return []Finding{{
		FP: Fingerprint(KindRuntimeMismatch), Kind: KindRuntimeMismatch, Severity: Problem,
		Title: "The container engine isn't the one core is set up for.",
		Why:   in.Engine.Mismatch + ". Every engine operation of the Hub answers 503 until it runs against the right engine.",
		Class: FixExplain,
		Steps: []string{
			"Check CONTAINER_RUNTIME in core's .env and the engine socket (PORTCULLIS_ENGINE_SOCKET): the runtime is chosen once by ./portcullis init and never switched.",
			"Restart the Hub against the right engine (./portcullis up).",
		},
		Inputs: Digest(in.Engine.Mismatch),
	}}
}

func limitsNotEnforced(in *Inputs) []Finding {
	type key struct{ instance, service string }
	missing := map[key][]string{}
	for _, r := range in.Runtime {
		if r.Err != "" {
			continue
		}
		k := key{r.Instance, r.Service}
		if r.WantMemory && r.Memory == 0 && !contains(missing[k], "memory") {
			missing[k] = append(missing[k], "memory")
		}
		if r.WantPids && r.PidsLimit == 0 && !contains(missing[k], "pids") {
			missing[k] = append(missing[k], "pids")
		}
	}
	keys := make([]key, 0, len(missing))
	for k := range missing {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].instance != keys[j].instance {
			return keys[i].instance < keys[j].instance
		}
		return keys[i].service < keys[j].service
	})
	var out []Finding
	for _, k := range keys {
		what := strings.Join(missing[k], " and ")
		out = append(out, Finding{
			FP: Fingerprint(KindLimitsNotEnforced, k.instance, k.service), Kind: KindLimitsNotEnforced, Severity: Warning,
			Title: fmt.Sprintf("%s's service %s runs without its %s limit.", k.instance, k.service, what),
			Why:   fmt.Sprintf("Its compose sets a %s limit, but the running container has none: the operator's user manager doesn't have the cgroup controllers delegated, so a runaway process can take the whole host's resources.", what),
			Class: FixExplain,
			Steps: []string{
				"Check that the memory and pids controllers are delegated to the operator: `cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers` must list both (cgroups v2; see Operations → Rootless Podman).",
				fmt.Sprintf("Then restart %s.", k.instance),
			},
			Instances: []string{k.instance},
			Inputs:    Digest([]any{k.instance, k.service, missing[k]}),
		})
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// scanPaths is the scans' paths, sorted.
func scanPaths(in *Inputs) []string {
	ps := make([]string, 0, len(in.Scans))
	for p := range in.Scans {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

func unmappedOwners(in *Inputs) []Finding {
	var out []Finding
	for _, p := range scanPaths(in) {
		s := in.Scans[p]
		if s.Tree || s.Report == nil || s.Report.Unmapped.N == 0 {
			continue
		}
		u := s.Report.Unmapped
		steps := []string{}
		if s.Report.IDMap != nil {
			if op, ok := s.Report.IDMap.UID.ToHost(0); ok {
				for _, rel := range u.Sample {
					if strings.HasSuffix(rel, "…") {
						continue // clipped: not the entry's real name
					}
					host := p
					if rel != "." {
						host = path.Join(p, rel)
					}
					if q, ok := ShellQuote(host); ok {
						steps = append(steps, fmt.Sprintf("On the host, as root: `sudo chown -R %d %s` (once).", op, q))
					}
				}
			}
		}
		if len(steps) == 0 {
			steps = append(steps, "On the host, as root, give the entries listed to the operator (sudo chown -R <operator> <path>), once.")
		}
		steps = append(steps, "Run the disk check again (Doctor → Check disks).")
		f := Finding{
			FP: Fingerprint(KindUnmappedOwner, p), Kind: KindUnmappedOwner, Severity: Warning,
			Title: fmt.Sprintf("%d entries in %s are owned by a host account outside Portcullis' id range.", u.N, p),
			Why:   "Under rootless Podman, the containers see such owners as 65534 (host root, another real user, or container id 65534 read the same): the folder fixer refuses to change them, and apps may not read them. Samples: " + strings.Join(u.Sample, ", ") + ".",
			Class: FixExplain, Steps: steps, Paths: []string{p},
			Inputs: Digest([]any{p, u.N, u.Sample}),
		}
		if s.Folder != "" {
			f.Folders = []string{s.Folder}
		}
		out = append(out, f)
	}
	return out
}

// selinuxType is a label's type field (user:role:type:level).
func selinuxType(label string) string {
	f := strings.Split(label, ":")
	if len(f) < 3 {
		return ""
	}
	return f[2]
}

func selinuxLabelMissing(in *Inputs) []Finding {
	if !in.Engine.SELinux {
		return nil
	}
	var out []Finding
	for _, p := range scanPaths(in) {
		s := in.Scans[p]
		if s.Folder == "" || s.Tree {
			continue // shared folders only
		}
		label := ""
		if s.Report != nil {
			label = s.Report.SELinux
		}
		denied := strings.Contains(strings.ToLower(s.Err), "permission denied")
		if !denied && (label == "" || selinuxType(label) == selinuxContainerType) {
			continue
		}
		why := "Its root is labelled " + label + ", not " + selinuxContainerType + ": with SELinux enforcing, rootless containers can't read it."
		if label == "" {
			why = "Its scan failed with permission denied: with SELinux enforcing, rootless containers can't read a folder that isn't labelled " + selinuxContainerType + "."
		}
		steps := []string{"Portcullis never relabels shared folders itself: on the host, as root, run once:"}
		qr, ok1 := ShellQuote(p + "(/.*)?")
		qp, ok2 := ShellQuote(p)
		if ok1 && ok2 {
			steps = append(steps, "semanage fcontext -a -t "+selinuxContainerType+" "+qr, "restorecon -R "+qp)
		} else {
			steps = append(steps, "semanage fcontext -a -t "+selinuxContainerType+" for the folder's path and everything under it, then restorecon -R on it.")
		}
		steps = append(steps, "Run the disk check again (Doctor → Check disks).")
		out = append(out, Finding{
			FP: Fingerprint(KindSELinuxLabelMissing, p), Kind: KindSELinuxLabelMissing, Severity: Warning,
			Title: fmt.Sprintf("Shared folder %s isn't labelled for containers.", p),
			Why:   why, Class: FixExplain, Steps: steps,
			Folders: []string{s.Folder}, Paths: []string{p},
			Inputs: Digest([]any{p, label, denied}),
		})
	}
	return out
}

func udpSourceRewritten(in *Inputs) []Finding {
	ports := map[string][]string{}
	for _, p := range in.Ports {
		if strings.ToLower(p.Protocol) != "udp" || p.Port <= 0 {
			continue
		}
		s := fmt.Sprintf("%d/udp", p.Port)
		if !contains(ports[p.Instance], s) {
			ports[p.Instance] = append(ports[p.Instance], s)
		}
	}
	ids := make([]string, 0, len(ports))
	for id := range ports {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Finding
	for _, id := range ids {
		out = append(out, Finding{
			FP: Fingerprint(KindUDPSourceRewritten, id), Kind: KindUDPSourceRewritten, Severity: Info,
			Title:     fmt.Sprintf("%s's UDP clients appear with a rewritten source address.", id),
			Why:       "Under rootless Podman, UDP traffic to a published port (" + strings.Join(ports[id], ", ") + ") arrives from one address inside the rootless network namespace, so per-client data (a DNS app's query log, rate limits) sees a single client.",
			Class:     FixExplain,
			Steps:     []string{"Nothing to fix: this is how rootless Podman forwards UDP. Use TCP where the app offers it if per-client data matters."},
			Instances: []string{id},
			Inputs:    Digest([]any{id, ports[id]}),
		})
	}
	return out
}
