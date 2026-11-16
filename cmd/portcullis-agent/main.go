// Command portcullis-agent is the worker's agent (contract §17.4–§17.7):
//
//	portcullis-agent run           serve the agent API inside the tunnel
//	portcullis-agent join          read a join code from stdin (never an argument)
//	portcullis-agent status        print the identity's state as JSON
//	portcullis-agent healthcheck   exit 0 while run is alive
//	portcullis-agent leave         wipe the identity
//
// Environment: AGENT_DATA (absolute, the same path on the host),
// AGENT_ENGINE (default tcp://socket-proxy-agent:2375), AGENT_RUNTIME
// (docker|podman, required), AGENT_BIND_ROOTS (colon list, default
// /srv:/mnt:/media), AGENT_UNPRIVILEGED_PORT_START (the host's, written
// by worker join).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/hub/internal/agent"
	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"
	"github.com/portcullis/hub/internal/servers"
)

// MaxJoinInput bounds what join reads from stdin.
const MaxJoinInput = 4 << 10

// healthFile is touched by run every few seconds; healthcheck reads it.
const healthFile = "agent.alive"

func main() {
	os.Exit(Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

// Main is the command (tests call it). Exit codes: 0 done, 1 failed,
// 2 usage.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: portcullis-agent run|join|status|healthcheck|leave")
		return 2
	}
	// The shared-folder fixer (pre-flight P7): the agent's own image runs
	// it as "portcullis-agent folderfix <mode> …", before any env is read.
	if args[0] == "folderfix" {
		return folderfix.Main(args[1:], stdout, stderr)
	}
	data := getenv("AGENT_DATA")
	if !path.IsAbs(data) || path.Clean(data) != data || data == "/" {
		fmt.Fprintln(stderr, "AGENT_DATA must be an absolute path (the agent's data dir, the same on the host)")
		return 2
	}
	store := agent.Store{Dir: data + "/identity"}
	switch args[0] {
	case "join":
		if len(args) > 1 {
			fmt.Fprintln(stderr, "the join code is a secret: paste it when asked, or pipe it in")
			return 2
		}
		return join(store, stdin, stdout, stderr)
	case "status":
		st := map[string]string{"state": store.State()}
		if p, err := store.Pins(); err == nil {
			st["server_id"], st["tunnel_ip"] = p.ServerID, p.TunnelIP
		}
		json.NewEncoder(stdout).Encode(st)
		return 0
	case "healthcheck":
		fi, err := os.Stat(path.Join(data, healthFile))
		if err != nil || time.Since(fi.ModTime()) > 30*time.Second {
			return 1
		}
		return 0
	case "leave":
		if err := store.Wipe(); err != nil {
			fmt.Fprintln(stderr, "leave:", err)
			return 1
		}
		fmt.Fprintln(stdout, "the worker's identity is gone")
		return 0
	case "run":
		if len(args) > 1 {
			fmt.Fprintln(stderr, "usage: portcullis-agent run")
			return 2
		}
		if err := run(data, getenv); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stderr, "usage: portcullis-agent run|join|status|healthcheck|leave")
	return 2
}

func join(store agent.Store, stdin io.Reader, stdout, stderr io.Writer) int {
	b, err := io.ReadAll(io.LimitReader(stdin, MaxJoinInput+1))
	if err != nil || len(b) > MaxJoinInput {
		fmt.Fprintln(stderr, "join: the code must be at most 4 KiB on stdin")
		return 2
	}
	code, err := servers.DecodeJoinCode(string(b))
	if err != nil {
		fmt.Fprintln(stderr, err) // never the code itself
		return 1
	}
	if err := store.SaveJoin(code); err != nil {
		fmt.Fprintln(stderr, "join:", err)
		return 1
	}
	fmt.Fprintf(stdout, "joined as %s (%s): start the agent to enrol\n", code.ServerID, code.TunnelIP)
	return 0
}

// parseRoots validates AGENT_BIND_ROOTS (absolute, clean, not /, no ..).
func parseRoots(v string) ([]string, error) {
	if strings.TrimSpace(v) == "" {
		v = "/srv:/mnt:/media"
	}
	var out []string
	for _, r := range strings.Split(v, ":") {
		r = strings.TrimSpace(r)
		if !path.IsAbs(r) || path.Clean(r) != r || r == "/" || strings.Contains(r, "$") {
			return nil, fmt.Errorf("AGENT_BIND_ROOTS: %q must be an absolute clean path other than /", r)
		}
		out = append(out, r)
	}
	return out, nil
}

func run(data string, getenv func(string) string) error {
	kind := runtime.Kind(getenv("AGENT_RUNTIME"))
	if kind != runtime.KindDocker && kind != runtime.KindPodman {
		return errors.New("AGENT_RUNTIME must be docker or podman")
	}
	roots, err := parseRoots(getenv("AGENT_BIND_ROOTS"))
	if err != nil {
		return err
	}
	portStart := 1024
	if v := getenv("AGENT_UNPRIVILEGED_PORT_START"); v != "" {
		if portStart, err = strconv.Atoi(v); err != nil || portStart < 0 || portStart > 65535 {
			return errors.New("AGENT_UNPRIVILEGED_PORT_START must be 0–65535")
		}
	}
	host := getenv("AGENT_ENGINE")
	if host == "" {
		host = "tcp://socket-proxy-agent:2375"
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	guard := docker.NewGuard(kind)
	engine, err := docker.New(host, guard)
	if err != nil {
		return err
	}
	go guard.Run(ctx, engine, 10*time.Second)
	cli := compose.NewCLI(host, guard)
	rt := dockerrt.New(cli, engine, dockerrt.Options{Kind: kind, Guard: guard, HelperImage: dockerrt.HelperImage})
	// The agent's own container and image (the fixer runs on it, P7),
	// and its compose working dir: the worker's install (./portcullis,
	// .env, docker-compose.worker.yml) is protected like the data dir
	// (A-H1). Unreadable: no start.
	// Its own container by id (R4-L1), never by a hostname lookup.
	self, err := agent.SelfContainerID(getenv, "/proc")
	if err != nil {
		return fmt.Errorf("the agent can't identify its own container (set AGENT_CONTAINER_ID): %v", err)
	}
	service := getenv("AGENT_SERVICE")
	if service == "" {
		service = "agent"
	}
	ui, err := agent.VerifySelf(ctx, rt, self, service, getenv("AGENT_SELF_IMAGE_ID"))
	if err != nil {
		return err
	}
	self = ui.ID
	selfImage := ui.Image
	install, err := agent.InstallDirOf(ui.Labels)
	if err != nil {
		return err
	}
	protected, err := protectedPaths(ctx, rt, getenv("AGENT_PROTECTED"))
	if err != nil {
		return err
	}
	protected = append(protected, install)
	// A2-M3: the alias checks compare by device and inode, so the install
	// dir and the engine's data root must be visible here (core mounts
	// both read-only at their host paths).
	if err := agent.CheckVisible(install, engineRoot(ctx, rt)); err != nil {
		return err
	}
	if sock := getenv("AGENT_ENGINE_SOCKET"); sock != "" {
		if !path.IsAbs(sock) || path.Clean(sock) != sock {
			return errors.New("AGENT_ENGINE_SOCKET must be an absolute clean path")
		}
		protected = append(protected, sock)
	}
	// A-H3: every folder root visible here; A-M2: nothing protected
	// inside a folder root (by path and by dev/inode).
	if err := agent.CheckRootsVisible(roots); err != nil {
		return fmt.Errorf("%v: mount each folder root into the agent at the same path", err)
	}
	if err := agent.CheckProtectedOutsideRoots(append(append([]string{}, protected...), data), roots); err != nil {
		return err
	}
	ownProject := ui.Labels["com.docker.compose.project"]
	ownContainers, ownNames, err := ownContainerIDs(ctx, rt, ownProject, ui.ID)
	if err != nil {
		return err
	}
	// An own project that is an instance's (portcullis-<id> with a
	// bundle on disk) is refused: the exemption would cover that instance.
	if id, ok := strings.CutPrefix(ownProject, runtime.ProjectPrefix); ok {
		if _, err := os.Stat(path.Join(data, "projects", id)); err == nil {
			return fmt.Errorf("the agent's compose project %s is an instance's (a bundle of %s exists): refusing to start", ownProject, id)
		}
	}
	api := agent.NewAPI(agent.APIConfig{DataDir: data, BindRoots: roots, Runtime: rt, Net: engine, SelfImage: selfImage, OwnProject: ownProject, OwnContainers: ownContainers, ReservedNames: ownNames,
		HelperImage: dockerrt.HelperImage, ComposeEnv: rt.Env(), Config: cli.Config, Protected: protected,
		DiskFree: func(ctx context.Context) (int64, bool) {
			i, err := engineInfoFor(ctx, rt)
			if err != nil || i.DiskTotal == 0 {
				return 0, false
			}
			// A margin: the engine needs room too.
			return i.DiskFree - 1<<30, i.DiskFree > 1<<30
		}})
	engineInfo := agent.EngineInfo(rt, portStart)
	info := func(ctx context.Context) (agentapi.Info, error) {
		i, err := engineInfo(ctx)
		if err != nil {
			return i, err
		}
		if i.PortBinds, err = agent.PortBinds(ctx, engine); err != nil {
			return i, err
		}
		i.Quarantined = api.Quarantined()
		i.OwnProject = ownProject
		i.QuarantineError = api.QuarantineError()
		return i, nil
	}
	a, err := agent.New(agent.Config{DataDir: data, Runtime: string(kind), BindRoots: roots, Info: info, Routes: api, Unhealthy: api.Unhealthy,
		OnNetwork: func(ctx context.Context, n agentapi.NetworkParams) error { return api.SetupNetwork(ctx, n, self) }})
	if err != nil {
		return err
	}
	// The bind-check backstop on every container start (A-H2b).
	// Every running container checked before anything is served (A2-H1).
	api.Sweep(ctx)
	go api.WatchStarts(ctx)
	// At every start (P35): the worker's portcullis-proxy and the agent on it.
	if n, err := a.Network(); err == nil {
		if err := api.SetupNetwork(ctx, n, self); err != nil {
			log.Printf("portcullis-proxy: %v", err)
		}
	}
	tc, err := a.TunnelConfig(ctx)
	if err != nil {
		return err
	}
	tun, err := agent.NewTunnel(tc)
	if err != nil {
		return err
	}
	defer tun.Close()
	a.AttachTunnel(tun)
	ctl, err := tun.Listen(agent.ControlPort)
	if err != nil {
		return err
	}
	dl, err := tun.Listen(agent.DataPort)
	if err != nil {
		return err
	}
	srv := agent.NewHTTPServer(a.Handler())
	srv.ErrorLog = log.New(io.Discard, "", 0) // handshake noise; never certificate contents
	go srv.Serve(tls.NewListener(ctl, a.TLSConfig()))
	go agent.ServeData(dl, api.HandleData)
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			os.WriteFile(path.Join(data, healthFile), nil, 0o600)
			now := time.Now()
			os.Chtimes(path.Join(data, healthFile), now, now)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	log.Printf("portcullis-agent %s: %s at %s", agent.Version, a.State(), tc.Address)
	select {
	case <-ctx.Done():
	case <-a.Refused():
		srv.Close()
		return agent.ErrEnrolRefused
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// ownContainerIDs are the agent's own containers (its own and its compose
// project's, by the labels read at start): the backstop's exemption is
// by container id, never by project name.
func ownContainerIDs(ctx context.Context, rt runtime.Instances, project, self string) (ids, names []string, err error) {
	ids = []string{self}
	units, err := rt.List(ctx, runtime.Filter{All: true})
	if err != nil {
		return nil, nil, fmt.Errorf("listing the agent's own containers: %v", err)
	}
	for _, u := range units {
		if u.ID == self || (project != "" && u.Project == project) {
			if u.ID != self {
				ids = append(ids, u.ID)
			}
			if u.Name != "" {
				names = append(names, u.Name)
			}
		}
	}
	// Its id prefixes too (a hostname): no bundle may take them (R4-L1).
	names = append(names, self[:12])
	return ids, names, nil
}

// engineRoot is the engine's data root ("" when unreadable: protectedPaths
// already refused that).
func engineRoot(ctx context.Context, rt runtime.Instances) string {
	if i, err := rt.Info(ctx); err == nil && len(i.ForbiddenRoots) > 0 {
		return i.ForbiddenRoots[0]
	}
	return ""
}

// engineInfoFor is the engine part of /v1/info (its disk: the data root).
func engineInfoFor(ctx context.Context, rt runtime.Instances) (agentapi.Info, error) {
	return agent.EngineInfo(rt, 0)(ctx)
}

// defaultProtected are host paths no bind may equal, contain or be inside
// (review C3): the engines' roots and run dirs (sockets), system dirs.
var defaultProtected = []string{"/var/lib/docker", "/var/lib/containers", "/var/lib/containerd", "/run", "/var/run",
	"/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/var/lib/kubelet"}

// protectedPaths: the defaults, the engine's data root (its Info, waited
// for at most 30 s: an engine the agent can't ask refuses the start) and
// AGENT_PROTECTED (a colon list of absolute paths).
func protectedPaths(ctx context.Context, rt runtime.Instances, extra string) ([]string, error) {
	out := append([]string{}, defaultProtected...)
	ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var info runtime.Info
	var err error
	for {
		if info, err = rt.Info(ictx); err == nil && len(info.ForbiddenRoots) > 0 {
			break
		}
		select {
		case <-ictx.Done():
			return nil, errors.New("the engine's data root can't be read (it must be protected from binds): is socket-proxy-agent up?")
		case <-time.After(time.Second):
		}
	}
	out = append(out, info.ForbiddenRoots...)
	for _, p := range strings.Split(extra, ":") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !path.IsAbs(p) || path.Clean(p) != p {
			return nil, fmt.Errorf("AGENT_PROTECTED: %q must be an absolute clean path", p)
		}
		out = append(out, p)
	}
	return out, nil
}
