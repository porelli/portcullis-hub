// Command portcullis-relay is a placed instance's relay on the primary
// (contract §5, §17.2): it listens on RELAY_LISTEN (:<port>[,…]) and
// forwards each request over link's data CONNECT (RELAY_LINK) to
// RELAY_TARGET (<instance>.<service>.relay) on the same port, with the
// bearer PORTCULLIS_RELAY_TOKEN. RELAY_APP_LABEL / RELAY_SERVER_LABEL name
// the offline page. `portcullis-relay healthcheck` checks the first port.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/portcullis/hub/internal/relay"
)

func main() { os.Exit(Main(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)) }

const usage = "usage: portcullis-relay [healthcheck]\n" +
	"env: RELAY_LISTEN=:<port>[,…] RELAY_TARGET=<instance>.<service>.relay RELAY_LINK=<ip>:3129 PORTCULLIS_RELAY_TOKEN=… RELAY_APP_LABEL RELAY_SERVER_LABEL\n"

// Main is the command; exit 0 done, 1 failed, 2 usage.
func Main(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	ports, err := relay.ParseListen(getenv("RELAY_LISTEN"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(args) == 1 && args[0] == "healthcheck" {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(ports[0]), 3*time.Second)
		if err != nil {
			return 1
		}
		c.Close()
		return 0
	}
	if len(args) > 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cfg := relay.Config{Ports: ports, Target: getenv("RELAY_TARGET"), Link: getenv("RELAY_LINK"), Token: getenv("PORTCULLIS_RELAY_TOKEN"),
		App: getenv("RELAY_APP_LABEL"), Server: getenv("RELAY_SERVER_LABEL")}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, err) // never the token
		return 2
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func run(cfg relay.Config) error {
	lns, err := cfg.Listen()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, len(lns))
	var srvs []*http.Server
	for i, ln := range lns {
		s := relay.NewServer(cfg.Handler(cfg.Ports[i]))
		s.ErrorLog = log.New(io.Discard, "", 0)
		srvs = append(srvs, s)
		go func() { errc <- s.Serve(ln) }()
	}
	log.Printf("portcullis-relay: %s on %v", cfg.Target, cfg.Ports)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range srvs {
		s.Shutdown(sctx)
	}
	return nil
}
