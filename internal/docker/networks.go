package docker

import (
	"context"
	"net/netip"

	"github.com/moby/moby/client"
)

// Network is the subset of a Docker network the Hub uses: its name and
// IPAM subnets (the VPN overlap guard, contract §3.3).
type Network struct {
	Name    string
	Subnets []netip.Prefix
}

// ListNetworks lists every network with its IPAM subnets.
func (c *Client) ListNetworks(ctx context.Context) ([]Network, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]Network, 0, len(res.Items))
	for _, n := range res.Items {
		nw := Network{Name: n.Name}
		for _, cfg := range n.IPAM.Config {
			if cfg.Subnet.IsValid() {
				nw.Subnets = append(nw.Subnets, cfg.Subnet)
			}
		}
		out = append(out, nw)
	}
	return out, nil
}
