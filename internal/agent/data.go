package agent

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
)

// PreambleTimeout: the data preamble must arrive this fast.
const PreambleTimeout = 5 * time.Second

// HandleData serves one data connection from link (ServeData checked its
// source): the preamble {"instance","service","port"} (≤ 1 KiB, within 5
// s) must name a routed service of a bundled project on a port its model
// routes (a traefik.http.services.*.loadbalancer.server.port label); the
// agent then dials that service's running container on the worker's
// portcullis-proxy and splices. Anything else closes the connection.
func (a *API) HandleData(c net.Conn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(PreambleTimeout))
	pre, err := agentapi.ReadPreamble(c)
	if err != nil {
		return
	}
	p := a.project(pre.Instance)
	if p == nil || !p.routes[pre.Service][pre.Port] {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := a.serviceAddr(ctx, pre.Instance, pre.Service)
	if err != nil {
		return
	}
	var d net.Dialer
	up, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(pre.Port)))
	if err != nil {
		return
	}
	defer up.Close()
	c.SetReadDeadline(time.Time{})
	splice(c, up)
}

// serviceAddr is a running container of the service, on portcullis-proxy,
// whose labels name the bundled project.
func (a *API) serviceAddr(ctx context.Context, instance, service string) (netip.Addr, error) {
	units, err := a.cfg.Runtime.List(ctx, runtime.Filter{Instance: instance, Service: service})
	if err != nil {
		return netip.Addr{}, err
	}
	for _, u := range units {
		if u.State != "running" || u.Labels[docker.LabelProject] != runtime.ProjectName(instance) {
			continue
		}
		ip, labels, err := a.cfg.Net.ContainerAddr(ctx, u.ID, ProxyNetwork)
		if err == nil && labels[docker.LabelProject] == runtime.ProjectName(instance) {
			return ip, nil
		}
	}
	return netip.Addr{}, io.EOF
}

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// SetupNetwork creates the worker's internal portcullis-proxy with the
// primary's subnet and range and attaches the agent (container self) at
// the Traefik address (pre-flight P35: at enrolment and at every start).
func (a *API) SetupNetwork(ctx context.Context, n agentapi.NetworkParams, self string) error {
	if err := validNetwork(n); err != nil {
		return err
	}
	if err := a.cfg.Net.EnsureNetwork(ctx, ProxyNetwork, n.ProxySubnet, n.ProxyIPRange, true, map[string]string{"io.portcullis.agent": "proxy"}); err != nil {
		return err
	}
	return a.cfg.Net.ConnectNetwork(ctx, ProxyNetwork, self, n.TraefikIP)
}

// PortBinds maps the engine's published ports to agentapi.PortBind
// (every container's: collisions are per server).
func PortBinds(ctx context.Context, n Net) ([]agentapi.PortBind, error) {
	pb, err := n.PortBinds(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]agentapi.PortBind, 0, len(pb))
	for _, p := range pb {
		out = append(out, agentapi.PortBind{Project: p.Labels[docker.LabelProject], Service: p.Labels[docker.LabelService], HostIP: p.HostIP, HostPort: p.HostPort, Proto: p.Proto})
	}
	return out, nil
}
