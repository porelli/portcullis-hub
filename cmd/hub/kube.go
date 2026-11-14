package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
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
func kubeRuntime(ctx context.Context, cfg *hub.Config, getenv func(string) string) (runtime.Instances, error) {
	self, err := selfImageFromEnv(getenv)
	if err != nil {
		return nil, err
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
	restCfg, icErr := rest.InClusterConfig()
	if icErr != nil {
		log.Printf("kubernetes: %v: every runtime operation answers 503", icErr)
		restCfg = &rest.Config{Host: "https://kubernetes.default.svc"}
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	coreEnv := readCoreEnv(cfg.ProjectDir)
	settings := kube.Settings{
		PodCIDR: coreEnv["PORTCULLIS_POD_CIDR"], ServiceCIDR: coreEnv["PORTCULLIS_SERVICE_CIDR"],
		TraefikServiceIP: coreEnv["PORTCULLIS_TRAEFIK_SERVICE_IP"], WGEdgeServiceIP: coreEnv["PORTCULLIS_WG_EDGE_SERVICE_IP"],
		Domain: cfg.Domain, CorePorts: templates.KubeCorePorts(coreEnv), NodeAddresses: strings.Fields(strings.ReplaceAll(coreEnv["PORTCULLIS_KUBE_NODE_ADDRESSES"], ",", " ")),
	}
	ex := kube.RemoteExec{Client: client, Config: restCfg}
	guard := kube.NewGuard(kube.GuardConfig{Client: client, Dynamic: dyn, AppsNamespace: apps, CoreNamespace: core, EdgeNamespace: edge, InCluster: icErr, HubImage: self, Exec: ex})
	roots, _ := hub.ParseBindRoots(cfg.OverrideBindRoots, cfg.ProjectHostDir)
	b, err := kube.New(kube.Config{Client: client, Dynamic: dyn, Namespace: apps, Settings: settings, HubImage: self, Resolver: kube.RegistryResolver{}, Exec: ex,
		Guard: guard, Context: coreEnv["PORTCULLIS_KUBE_CONTEXT"], RuntimeRoots: strings.Fields(coreEnv["PORTCULLIS_RUNTIME_ROOTS"]), BindRoots: roots, EdgeNamespace: edge})
	if err != nil {
		return nil, err
	}
	go guard.Run(ctx, time.Minute)
	select {
	case <-guard.Verified():
	case <-time.After(engineStartWait):
		log.Printf("kubernetes: the cluster isn't verified after %s: starting anyway, runtime operations answer 503 until it is (%v)", engineStartWait, guard.Err())
	}
	return b, nil
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
