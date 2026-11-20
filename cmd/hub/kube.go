package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/gatelogs"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/leader"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"
	"github.com/portcullis/hub/internal/templates"
)

// selfImageFromEnv is HUB_SELF_IMAGE: required under Kubernetes, pinned
// by digest (the helper pods' image; admission pins helpers to it).
func selfImageFromEnv(getenv func(string) string) (string, error) {
	v := strings.TrimSpace(getenv("HUB_SELF_IMAGE"))
	if v == "" {
		return "", fmt.Errorf("HUB_SELF_IMAGE is required under HUB_CONTAINER_RUNTIME=kubernetes")
	}
	if !strings.Contains(v, "@sha256:") || !docker.PinnedImage(v) {
		return "", fmt.Errorf("HUB_SELF_IMAGE %q must be pinned by digest (name@sha256:<64 hex>)", v)
	}
	return v, nil
}

// saNamespaceFile is the in-cluster ServiceAccount's namespace (the
// core namespace: the Hub runs there).
const saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// kubeRuntime builds the kube backend and its cluster guard (started at
// once, then every minute, and before every deploy). A failing in-cluster
// configuration doesn't stop the start: the guard fails closed (503).
func kubeRuntime(ctx context.Context, cfg *hub.Config, getenv func(string) string) (runtime.Instances, *leader.Fence, error) {
	self, err := selfImageFromEnv(getenv)
	if err != nil {
		return nil, nil, err
	}
	identity, err := podNameFromEnv(getenv)
	if err != nil {
		return nil, nil, err
	}
	cfg.SelfImage = self
	apps := strings.TrimSpace(getenv("HUB_APPS_NAMESPACE"))
	if apps == "" {
		apps = "portcullis-apps"
	}
	edge := strings.TrimSpace(getenv("HUB_EDGE_NAMESPACE"))
	if edge == "" {
		edge = kube.EdgeNamespace
	}
	core := "portcullis"
	if b, err := os.ReadFile(saNamespaceFile); err == nil && strings.TrimSpace(string(b)) != "" {
		core = strings.TrimSpace(string(b))
	}
	cfg.AppsNamespace, cfg.CoreNamespace = apps, core
	restCfg, icErr := rest.InClusterConfig()
	if icErr != nil {
		log.Printf("kubernetes: %v: every runtime operation answers 503", icErr)
		restCfg = &rest.Config{Host: "https://kubernetes.default.svc"}
	}
	// The Lease's own client is never gated (it is how this Hub comes to
	// lead); every other request that changes the cluster asks the write
	// gate first (contract §20.5).
	leaseClient, err := kubernetes.NewForConfig(rest.CopyConfig(restCfg))
	if err != nil {
		return nil, nil, err
	}
	fence := leader.New(leader.Config{Client: leaseClient, Namespace: core, Name: leaseName, Identity: identity})
	restCfg.Wrap(kube.GateWrites)
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, err
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, err
	}
	coreEnv := readCoreEnv(cfg.ProjectDir)
	settings := kube.Settings{
		PodCIDR: coreEnv["PORTCULLIS_POD_CIDR"], ServiceCIDR: coreEnv["PORTCULLIS_SERVICE_CIDR"],
		TraefikServiceIP: coreEnv["PORTCULLIS_TRAEFIK_SERVICE_IP"], WGEdgeServiceIP: coreEnv["PORTCULLIS_WG_EDGE_SERVICE_IP"],
		Domain: cfg.Domain, CorePorts: templates.KubeCorePorts(coreEnv), NodeAddresses: strings.Fields(strings.ReplaceAll(coreEnv["PORTCULLIS_KUBE_NODE_ADDRESSES"], ",", " ")),
		APIAddresses: apiAddresses(coreEnv["PORTCULLIS_KUBE_API_ENDPOINTS"]),
		HA:           haFromEnv(getenv),
	}
	cfg.HA = settings.HA
	cfg.BackupDestination = getenv("HUB_BACKUP_DESTINATION") == "set"
	if settings.TraefikPeer, err = traefikPeerFromEnv(getenv, settings.HA, core); err != nil {
		return nil, nil, err
	}
	ex := kube.RemoteExec{Client: client, Config: restCfg}
	guard := kube.NewGuard(kube.GuardConfig{Client: client, Dynamic: dyn, AppsNamespace: apps, CoreNamespace: core, EdgeNamespace: edge, InCluster: icErr, HubImage: self, Exec: ex})
	roots, _ := hub.ParseBindRoots(cfg.OverrideBindRoots, cfg.ProjectHostDir)
	b, err := kube.New(kube.Config{Client: client, Dynamic: dyn, Namespace: apps, Settings: settings, HubImage: self, Resolver: kube.RegistryResolver{}, Exec: ex,
		Guard: guard, Context: coreEnv["PORTCULLIS_KUBE_CONTEXT"], RuntimeRoots: strings.Fields(coreEnv["PORTCULLIS_RUNTIME_ROOTS"]), BindRoots: roots, EdgeNamespace: edge, CoreNamespace: core})
	if err != nil {
		return nil, nil, err
	}
	// Not waited for here: before the Hub leads, the NetworkPolicy probe
	// (a write) is refused by the fence, so the first check can't pass.
	// The Hub kicks the guard once leading (after its start-time
	// republish, Hub.SetAfterStartPublish); until it verifies, runtime
	// operations answer 503.
	go guard.Run(ctx, time.Minute)
	return b, fence, nil
}

// haFromEnv is HUB_HA (contract §20.1 "HA mode"): only exactly "on"
// turns HA on; core's chart sets it with ha.enabled.
func haFromEnv(getenv func(string) string) bool { return getenv("HUB_HA") == "on" }

// traefikPeerFromEnv is HUB_TRAEFIK_PEER, Traefik as the routed ports'
// NetworkPolicy peer in the admission params' form (core's chart passes
// the params' traefik value, kube_traefik_peer). Only the two values
// core writes are taken (HA Task 13 review I2): the HA DaemonSet's
// portcullis-ingress:app.kubernetes.io/name=traefik, or
// <core namespace>:portcullis.io/component=traefik (the Hub's own
// namespace); anything else refuses the start, so no value can make
// another namespace's or an app's pods a peer of every routed port.
// Unset = the value for the mode.
func traefikPeerFromEnv(getenv func(string) string, ha bool, core string) (kube.Peer, error) {
	v := getenv("HUB_TRAEFIK_PEER")
	if v == "" {
		return kube.DefaultTraefikPeer(ha, core), nil
	}
	for _, known := range []kube.Peer{kube.DefaultTraefikPeer(true, core), kube.DefaultTraefikPeer(false, core)} {
		if v == known.String() {
			return known, nil
		}
	}
	return kube.Peer{}, fmt.Errorf("HUB_TRAEFIK_PEER must be %s (HA) or %s (the core namespace %s), got %q",
		kube.DefaultTraefikPeer(true, core), kube.DefaultTraefikPeer(false, core), core, v)
}

// gateLogSourcesFromEnv is HUB_GATE_LOG_SOURCES (contract §20.10): unset
// or "files" = the gates' logs and wg's status from their mounted files;
// "http" (set by core's chart in HA) = from each replica's read-only port,
// Kubernetes only. Anything else refuses the start.
func gateLogSourcesFromEnv(getenv func(string) string, kind runtime.Kind) (bool, error) {
	switch v := getenv("HUB_GATE_LOG_SOURCES"); v {
	case "", "files":
		return false, nil
	case "http":
		if kind != runtime.KindKubernetes {
			return false, fmt.Errorf("HUB_GATE_LOG_SOURCES=http needs HUB_CONTAINER_RUNTIME=kubernetes")
		}
		return true, nil
	default:
		return false, fmt.Errorf("HUB_GATE_LOG_SOURCES must be files or http, got %q", v)
	}
}

// coreReplicas is the kube backend's lister of a core component's pods.
type coreReplicas interface {
	CoreReplicas(component string, o kube.ReplicaOptions) gatelogs.Lister
}

// gateReplicasFromEnv is HUB_GATE_REPLICAS: the gates' replica count the
// chart runs (ha.gateReplicas), 1–16; unset = unknown (missing replicas
// are then inferred from the ordinals seen). Anything else refuses the
// start.
func gateReplicasFromEnv(getenv func(string) string) (int, error) {
	v := getenv("HUB_GATE_REPLICAS")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 16 || strconv.Itoa(n) != v {
		return 0, fmt.Errorf("HUB_GATE_REPLICAS must be an integer 1-16, got %q", v)
	}
	return n, nil
}

// wireGateLogs points the opened log, the access log and wg's status at
// the replicas' ports (HUB_GATE_LOG_SOURCES=http): the chart mounts none
// of their volumes then, so the file settings are cleared (the Hub
// neither reads nor prunes group-gate-data: each gate prunes its own).
func wireGateLogs(cfg *hub.Config, rt runtime.Instances, getenv func(string) string) error {
	b, ok := rt.(coreReplicas)
	if !ok {
		return fmt.Errorf("HUB_GATE_LOG_SOURCES=http: the runtime can't list the core pods")
	}
	n, err := gateReplicasFromEnv(getenv)
	if err != nil {
		return err
	}
	gate := kube.ReplicaOptions{StatefulSet: true, Expected: n}
	cfg.GroupGateDataDir, cfg.MCPGateDataDir, cfg.VPNStatusFile = "", "", ""
	cfg.GateLogs = &hub.GateLogSources{
		Opened:   gatelogs.Replicas{Service: "group-gate", Port: gatelogs.GroupGatePort, Lister: b.CoreReplicas("group-gate", gate)},
		Access:   &gatelogs.Tail{R: gatelogs.Replicas{Service: "mcp-gate", Port: gatelogs.MCPGatePort, Lister: b.CoreReplicas("mcp-gate", gate)}},
		WGStatus: gatelogs.Replicas{Service: "wg", Port: gatelogs.WGStatusPort, Lister: b.CoreReplicas("wg", kube.ReplicaOptions{})},
	}
	log.Printf("gate logs: read from the replicas' ports (group-gate :%d, mcp-gate :%d, wg :%d)", gatelogs.GroupGatePort, gatelogs.MCPGatePort, gatelogs.WGStatusPort)
	return nil
}

// leaseName is the Hub's Lease in the core namespace (contract §20.5).
const leaseName = "portcullis-hub"

// podNameFromEnv is the Lease identity: POD_NAME (the chart's downward
// API), required. Never the hostname: a spec.hostname override or a
// hostNetwork pod could give two Hubs one identity, and both would take
// the Lease as theirs.
func podNameFromEnv(getenv func(string) string) (string, error) {
	if v := strings.TrimSpace(getenv("POD_NAME")); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("POD_NAME is required under HUB_CONTAINER_RUNTIME=kubernetes (the Lease identity, contract §20.5)")
}

// readCoreEnv is core's env subset (<ProjectDir>/.env: KEY=value lines;
// quotes trimmed).
func readCoreEnv(projectDir string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(projectDir, ".env"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return out
}

// runtimeVerified is closed once the runtime's guard first verified
// (docker: the engine guard; kubernetes: the cluster guard).
func runtimeVerified(rt runtime.Instances, g *docker.Guard) <-chan struct{} {
	if g != nil {
		return g.Verified()
	}
	if v, ok := rt.(interface{ Verified() <-chan struct{} }); ok {
		return v.Verified()
	}
	return make(chan struct{})
}

// apiAddresses are the addresses of PORTCULLIS_KUBE_API_ENDPOINTS
// (<ip>:<port>, comma or space separated).
func apiAddresses(v string) []string {
	var out []string
	for _, e := range strings.Fields(strings.ReplaceAll(v, ",", " ")) {
		if h, _, err := net.SplitHostPort(e); err == nil {
			out = append(out, h)
		} else {
			out = append(out, e)
		}
	}
	return out
}
