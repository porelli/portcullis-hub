// Command portcullis-nodeagent is the cluster node's host service
// (contract §20.3, §20.4, §20.11), installed as
// /usr/local/lib/portcullis/nodeagent by join.sh:
//
//	nodeagent join             join the cluster; the join code on stdin (never an argument)
//	nodeagent serve            the API on <mesh ip>:7443, the echo on :7444, the probes
//	nodeagent mesh-up          bring pcmesh up with the stored plan (the unit's ExecStartPre)
//	nodeagent checks [--json] [--dry-run]   the host checks
//	nodeagent version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	na "github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/nodeagent/host"
	"github.com/portcullis/hub/internal/version"
)

func main() {
	os.Exit(Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const usage = "usage: nodeagent join|serve|mesh-up|checks [--json] [--dry-run]|version"

// Main is the command. Exit codes: 0 done, 1 failed, 2 usage.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, version.Version)
		return 0
	case "checks":
		return checks(ctx, args[1:], stdout, stderr)
	case "join":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "nodeagent join takes no arguments: the join code comes on stdin (it is a secret)")
			return 2
		}
		return join(ctx, stdin, stdout, stderr, log)
	case "mesh-up", "serve":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		a, closeWG, err := loaded(log)
		if err != nil {
			fmt.Fprintln(stderr, "nodeagent:", err)
			return 1
		}
		defer closeWG()
		if err := a.MeshUp(ctx); err != nil {
			fmt.Fprintln(stderr, "nodeagent:", err)
			return 1
		}
		if args[0] == "mesh-up" {
			return 0
		}
		if err := serve(ctx, a, log); err != nil {
			fmt.Fprintln(stderr, "nodeagent:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
}

func newAgent(log *slog.Logger) (*host.Agent, func(), error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, func() {}, fmt.Errorf("WireGuard control: %v", err)
	}
	a := host.New(host.Config{Version: version.Version, WG: wg, Log: log})
	return a, func() { wg.Close() }, nil
}

func loaded(log *slog.Logger) (*host.Agent, func(), error) {
	if os.Geteuid() != 0 {
		return nil, func() {}, errors.New("run it as root")
	}
	a, closeWG, err := newAgent(log)
	if err != nil {
		return nil, closeWG, err
	}
	if err := a.Load(); err != nil {
		closeWG()
		return nil, func() {}, err
	}
	return a, closeWG, nil
}

func checks(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	asJSON, dry := false, false
	for _, f := range args {
		switch f {
		case "--json":
			asJSON = true
		case "--dry-run":
			dry = true
		default:
			fmt.Fprintln(stderr, usage)
			return 2
		}
	}
	a := host.New(host.Config{Version: version.Version})
	c := a.HostChecks(ctx)
	if asJSON {
		json.NewEncoder(stdout).Encode(c)
	} else {
		for _, x := range c.Checks {
			mark := "ok  "
			if !x.OK {
				mark = "FAIL"
			}
			fmt.Fprintf(stdout, "%s %-20s %s\n", mark, x.ID, x.Detail)
		}
		fmt.Fprintf(stdout, "memory %d bytes, %d CPUs, model %q: class %s suggested\n", c.MemBytes, c.CPUs, c.Model, c.ClassSuggestion)
	}
	if dry {
		return 0
	}
	for _, x := range c.Checks {
		if !x.OK && (x.ID == "wireguard" || x.ID == "ports" || x.ID == "mesh_subnet") {
			return 1
		}
	}
	return 0
}

func join(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, log *slog.Logger) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "nodeagent join: run it as root")
		return 1
	}
	a, closeWG, err := newAgent(log)
	if err != nil {
		fmt.Fprintln(stderr, "nodeagent join:", err)
		return 1
	}
	defer closeWG()
	c := &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second}}
	if err := a.Join(ctx, stdin, stdout, host.JoinDeps{HTTP: c}); err != nil {
		fmt.Fprintln(stderr, "nodeagent join:", err)
		return 1
	}
	return 0
}

// serve runs the API, the echo, the probes and a periodic re-apply of
// the mesh (the rules kept in place) until ctx ends.
func serve(ctx context.Context, a *host.Agent, log *slog.Logger) error {
	st := a.State()
	ln, err := net.Listen("tcp4", net.JoinHostPort(st.MeshIP, fmt.Sprint(host.APIPort)))
	if err != nil {
		return fmt.Errorf("the API listener: %v", err)
	}
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(st.MeshIP, fmt.Sprint(na.EchoPort)))
	if err != nil {
		ln.Close()
		return fmt.Errorf("the echo listener: %v", err)
	}
	srv := &http.Server{Handler: a.Handler(ctx), TLSConfig: a.TLSConfig(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
	go a.ServeEcho(ctx, pc)
	go a.RunProbes(ctx)
	go a.RunRTT(ctx)
	go a.RunRenewal(ctx)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := a.MeshUp(ctx); err != nil {
					log.Warn("mesh re-apply", "err", err.Error())
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("nodeagent serving", "id", st.ID, "addr", ln.Addr().String(), "version", version.Version)
	if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
