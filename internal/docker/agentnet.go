package docker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// The worker agent's engine calls (multi-server Task 6; through
// socket-proxy-agent, NETWORKS + POST): its portcullis-proxy network,
// its own attachment at the Traefik address, the published ports and the
// containers' addresses for the data path.

// PortBind is one published host port of a container.
type PortBind struct {
	ContainerID string
	Labels      map[string]string
	HostIP      string
	HostPort    int
	Proto       string
}

// PortBinds lists every container's published host ports.
func (c *Client) PortBinds(ctx context.Context) ([]PortBind, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ContainerList(ctx, client.ContainerListOptions{All: false})
	if err != nil {
		return nil, err
	}
	var out []PortBind
	for _, s := range res.Items {
		for _, p := range s.Ports {
			if p.PublicPort == 0 {
				continue
			}
			ip := ""
			if p.IP.IsValid() {
				ip = p.IP.String()
			}
			out = append(out, PortBind{ContainerID: s.ID, Labels: s.Labels, HostIP: ip, HostPort: int(p.PublicPort), Proto: p.Type})
		}
	}
	return out, nil
}

// ContainerAddr is a running container's IPv4 address on one network.
func (c *Client) ContainerAddr(ctx context.Context, id, net string) (netip.Addr, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return netip.Addr{}, nil, err
	}
	ct := res.Container
	if ct.State == nil || !ct.State.Running || ct.NetworkSettings == nil {
		return netip.Addr{}, nil, errors.New("the container isn't running")
	}
	var labels map[string]string
	if ct.Config != nil {
		labels = ct.Config.Labels
	}
	ep, ok := ct.NetworkSettings.Networks[net]
	if !ok || ep == nil || !ep.IPAddress.Is4() {
		return netip.Addr{}, labels, fmt.Errorf("the container has no address on %s", net)
	}
	return ep.IPAddress, labels, nil
}

// EnsureNetwork creates network name (bridge, internal as asked) with
// exactly subnet and ipRange unless it exists; an existing one must have
// that subnet.
func (c *Client) EnsureNetwork(ctx context.Context, name string, subnet, ipRange netip.Prefix, internal bool, labels map[string]string) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if res, err := c.api.NetworkInspect(ctx, name, client.NetworkInspectOptions{}); err == nil {
		for _, cfg := range res.Network.IPAM.Config {
			if cfg.Subnet == subnet {
				return nil
			}
		}
		return fmt.Errorf("network %s exists with another subnet than %s", name, subnet)
	}
	_, err := c.api.NetworkCreate(ctx, name, client.NetworkCreateOptions{Driver: "bridge", Internal: internal, Labels: labels,
		IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: subnet, IPRange: ipRange}}}})
	return err
}

// ConnectNetwork attaches container to network at ip (already attached:
// nothing to do).
func (c *Client) ConnectNetwork(ctx context.Context, net, container string, ip netip.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if addr, _, err := c.ContainerAddr(ctx, container, net); err == nil {
		if addr == ip {
			return nil
		}
		return fmt.Errorf("the agent is on %s at %s, not %s", net, addr, ip)
	}
	_, err := c.api.NetworkConnect(ctx, net, client.NetworkConnectOptions{Container: container,
		EndpointConfig: &network.EndpointSettings{IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: ip}}})
	return err
}
