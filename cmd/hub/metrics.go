package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/portcullis/hub/internal/httpapi"
	"github.com/portcullis/hub/internal/hub"
)

// metricsBindAddr resolves HUB_METRICS_ADDR (host:port) to the one
// address to bind (contract §16.2): never a wildcard or a loopback, and
// the name must resolve to exactly one address that is the Hub's own
// (its address on portcullis-metrics-hub). Fail closed: an error stops
// the start.
func metricsBindAddr(addr string, lookup func(host string) ([]netip.Addr, error), own func() ([]netip.Addr, error)) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("HUB_METRICS_ADDR %q: want host:port", addr)
	}
	if host == "" {
		return "", fmt.Errorf("HUB_METRICS_ADDR %q: a wildcard address is refused", addr)
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = lookup(host); err != nil {
		return "", fmt.Errorf("HUB_METRICS_ADDR %q: %s doesn't resolve: %v", addr, host, err)
	}
	if len(ips) != 1 {
		return "", fmt.Errorf("HUB_METRICS_ADDR %q: %s resolves to %d addresses, want exactly one", addr, host, len(ips))
	}
	ip := ips[0].Unmap()
	switch {
	case ip.IsUnspecified():
		return "", fmt.Errorf("HUB_METRICS_ADDR %q: a wildcard address is refused", addr)
	case ip.IsLoopback():
		return "", fmt.Errorf("HUB_METRICS_ADDR %q: a loopback address is refused", addr)
	}
	mine, err := own()
	if err != nil {
		return "", fmt.Errorf("HUB_METRICS_ADDR: the Hub's own addresses: %v", err)
	}
	if !slices.ContainsFunc(mine, func(a netip.Addr) bool { return a.Unmap() == ip }) {
		return "", fmt.Errorf("HUB_METRICS_ADDR %q: %s isn't one of the Hub's own addresses", addr, ip)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// lookupHost resolves a name (the compose alias hub-metrics).
func lookupHost(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ownAddrs are the addresses of the Hub's interfaces.
func ownAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out, nil
}

// serveMetrics starts the metrics listener on HUB_METRICS_ADDR ("" = none):
// a configured listener that can't bind its own address stops the start.
func serveMetrics(ctx context.Context, addr string, h *hub.Hub) {
	if addr == "" {
		return
	}
	bind, err := metricsBindAddr(addr, lookupHost, ownAddrs)
	if err != nil {
		log.Fatalf("%v", err)
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("HUB_METRICS_ADDR: listen on %s: %v", bind, err)
	}
	srv := &http.Server{Handler: httpapi.MetricsHandler(h.UsageCollector(), h.NoteMetricsScrape),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics listener: %v", err)
		}
	}()
	log.Printf("metrics listener on %s (usage metrics, contract §16.2)", bind)
}
