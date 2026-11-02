package templates

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Core-owned names a template may not use (contract §5, §12): the
// extra-domain sign-in plumbing the Hub renders itself, core's networks,
// and the DNS name of the domains service.

// coreNetworks are core's networks (compose keys; their Docker names are
// these or portcullis_<key>). Templates join only portcullis-proxy.
var coreNetworks = map[string]bool{
	"portcullis": true, "portcullis-auth": true, "portcullis-certs": true, "portcullis-domains": true,
	"domains-egress": true, "socket-proxy-traefik": true, "socket-proxy-hub": true, "monitoring": true, "alerting": true,
}

// reservedRefs may not appear anywhere in a template's compose file: the
// Hub renders portcullis-auth-ext and the portcullis-oauth2-<id>_<router>
// sign-in routers to forward-auth-ext on extra-domain hosts itself.
var reservedRefs = []string{"forward-auth-ext", "portcullis-auth-ext", "portcullis-oauth2-"}

// reservedDNSNames: a container answering to one of these on a network it
// shares with a core service could intercept that service's traffic.
var reservedDNSNames = map[string]bool{"domains": true}

func isCoreNetwork(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return coreNetworks[n] || coreNetworks[strings.TrimPrefix(n, "portcullis_")]
}

// checkCoreRefs rejects a compose file that references the reserved
// sign-in names, joins a core network (by external name or network_mode
// container:), or answers to a reserved DNS name (service name,
// container_name, hostname, network alias).
func checkCoreRefs(compose []byte) error {
	low := strings.ToLower(string(compose))
	for _, r := range reservedRefs {
		if strings.Contains(low, r) {
			return fmt.Errorf("compose.yml references %q: the extra-domain sign-in (forward-auth-ext, portcullis-auth-ext, portcullis-oauth2-*) is rendered by the Hub only", strings.TrimSuffix(r, "-"))
		}
	}
	var doc struct {
		Services map[string]struct {
			ContainerName string    `yaml:"container_name"`
			Hostname      string    `yaml:"hostname"`
			NetworkMode   string    `yaml:"network_mode"`
			Networks      yaml.Node `yaml:"networks"`
		} `yaml:"services"`
		Networks map[string]*struct {
			Name     string      `yaml:"name"`
			External interface{} `yaml:"external"`
		} `yaml:"networks"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return fmt.Errorf("compose.yml: %w", err)
	}
	keys := make([]string, 0, len(doc.Networks))
	for k := range doc.Networks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n := doc.Networks[k]
		ext := false
		if n != nil {
			switch v := n.External.(type) {
			case bool:
				ext = v
			case map[string]interface{}:
				ext = true
				if s, ok := v["name"].(string); ok && isCoreNetwork(s) {
					return fmt.Errorf("network %s joins the core network %s", k, s)
				}
			}
			if n.Name != "" && isCoreNetwork(n.Name) {
				return fmt.Errorf("network %s is named %s, a core network", k, n.Name)
			}
		}
		if ext && (n == nil || n.Name == "") && isCoreNetwork(k) {
			return fmt.Errorf("network %s is a core network (templates join only portcullis-proxy)", k)
		}
	}
	svcs := make([]string, 0, len(doc.Services))
	for s := range doc.Services {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	for _, name := range svcs {
		s := doc.Services[name]
		for _, dn := range []string{name, s.ContainerName, s.Hostname} {
			if reservedDNSNames[strings.ToLower(strings.TrimSpace(dn))] {
				return fmt.Errorf("service %s: the DNS name %q is reserved for core's domains service", name, dn)
			}
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.NetworkMode)), "container:") {
			return fmt.Errorf("service %s: network_mode %s joins another container's network namespace", name, s.NetworkMode)
		}
		if s.Networks.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(s.Networks.Content); i += 2 {
				net, cfg := s.Networks.Content[i].Value, s.Networks.Content[i+1]
				var c struct {
					Aliases []string `yaml:"aliases"`
				}
				if cfg.Kind == yaml.MappingNode {
					if err := cfg.Decode(&c); err != nil {
						return fmt.Errorf("service %s: network %s: %w", name, net, err)
					}
				}
				for _, a := range c.Aliases {
					if reservedDNSNames[strings.ToLower(strings.TrimSpace(a))] {
						return fmt.Errorf("service %s: network alias %q is reserved for core's domains service", name, a)
					}
				}
			}
		}
	}
	return nil
}
