package aigate

import (
	"strconv"

	"github.com/portcullis/hub/internal/templates"
)

// Names and URLs of the resources (contract §15.1, §3.2). The alias and
// the router are the T8 helpers' portcullis-mcp-<instance>--<companion>
// (the "--" separator: instance ids and companion names never contain
// it, so the pair is unambiguous).

// CompanionScope is a companion's scope: mcp:<instance>.<companion>.
func CompanionScope(instance, companion string) string { return "mcp:" + instance + "." + companion }

// Alias is the companion service's alias on portcullis-proxy.
func Alias(instance, companion string) string { return templates.MCPAlias(instance, companion) }

// Router is the companion's Traefik router name (= the alias).
func Router(instance, companion string) string { return templates.MCPAlias(instance, companion) }

// AliasFits reports whether the alias is one DNS label (≤ 63).
func AliasFits(instance, companion string) bool { return templates.AliasFits(instance, companion) }

// Upstream is the gate's upstream URL of a companion:
// http://<alias>:<port><path>.
func Upstream(instance, companion string, port int, path string) string {
	return "http://" + Alias(instance, companion) + ":" + strconv.Itoa(port) + path
}

// CompanionURL is a companion's canonical URL (its audience):
// https://<host of the router><public_path>.
func CompanionURL(host, publicPath string) string { return "https://" + host + publicPath }

// Issuer is the realm's public issuer.
func Issuer(domain string) string { return "https://auth." + domain + "/realms/portcullis" }

// AggregateURL, AdminURL, PeopleURL are the fixed resources' URLs.
func AggregateURL(domain string) string { return "https://mcp." + domain + "/mcp" }

// AdminURL is the Portcullis admin resource.
func AdminURL(domain string) string { return "https://hub." + domain + "/mcp" }

// PeopleURL is the Portcullis people resource.
func PeopleURL(domain string) string { return "https://people." + domain + "/mcp" }

// Fixed scopes.
const (
	ScopeAll    = "mcp:all"
	ScopeAdmin  = "mcp:portcullis.admin"
	ScopePeople = "mcp:portcullis.people"
)
