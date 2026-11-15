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
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
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
	rt := dockerrt.New(compose.NewCLI(host, guard), engine, dockerrt.Options{Kind: kind, Guard: guard})
	a, err := agent.New(agent.Config{DataDir: data, Runtime: string(kind), BindRoots: roots, Info: agent.EngineInfo(rt, portStart)})
	if err != nil {
		return err
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
	go agent.ServeData(dl, nil) // Task 6 serves the data path
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
