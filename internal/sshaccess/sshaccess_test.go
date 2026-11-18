package sshaccess

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/state"
)

var update = flag.Bool("update", false, "rewrite testdata/golden")

var now = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

// example is spec §9.1: web-1 and web-2 in web; ssh_web → web
// {username}; ssh_admins → all {username} sudo; ssh_deploy → web deploy.
func example() Input {
	st := state.SSHState{Settings: state.SSHSettings{Enabled: true}}
	st.EnsureBuiltins()
	st.HostGroups["web"] = state.SSHHostGroup{Label: "Web servers"}
	st.Hosts = map[string]state.SSHHost{
		"web-1": {Names: []string{"web-1.example.com"}, Addrs: []string{"192.0.2.11"}, HostGroups: []string{"web"}, Managed: true, HostKey: "ssh-ed25519 AAAA", SudoChecked: true}, // reported: no account with sudo
		"web-2": {Names: []string{"web-2.example.com"}, Addrs: []string{"192.0.2.12"}, HostGroups: []string{"web"}, Managed: true, HostKey: "ssh-ed25519 BBBB"},
	}
	st.Grants = []state.SSHGrant{
		{ID: "g-web", Group: "ssh_web", GroupID: 11, HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "none"},
		{ID: "g-admins", Group: "ssh_admins", GroupID: 12, HostGroup: "all", Accounts: []string{"{username}"}, Sudo: "full"},
		{ID: "g-deploy", Group: "ssh_deploy", GroupID: 13, HostGroup: "web", Accounts: []string{"deploy"}, Sudo: "none"},
	}
	st.UIDs = map[string]int{"alice": 20001, "bob": 20002}
	st.UIDsUsed = []int{20001, 20002}
	return Input{
		State: st,
		Members: map[string]map[string]int{
			"alice": {"ssh_web": 11, "ssh_admins": 12},
			"bob":   {"ssh_web": 11, "ssh_deploy": 13},
			"carol": {"other": 20},
		},
		Now:         now,
		UserCAs:     []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXf2yZXNFwHqiadxQBruvDLwOZYX4l4+MUIDqyknOMZ portcullis-user-ca"},
		RevokedKeys: []string{},
	}
}

func mustCompile(t *testing.T, in Input) *Compiled {
	t.Helper()
	c, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from golden:\n got %s\nwant %s", name, got, want)
	}
}

func js(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

func TestCompileExampleGolden(t *testing.T) {
	c := mustCompile(t, example())
	web := c.Roles["web"]
	if strings.Join(web.Principals, ",") != "s:deploy@web,u:alice@web,u:bob@web" || web.Extensions != "permit-pty" || web.MaxTTLSeconds != 8*3600 {
		t.Errorf("hg-web %+v", web)
	}
	all := c.Roles["all"]
	if strings.Join(all.Principals, ",") != "up:alice@all" || all.MaxTTLSeconds != 4*3600 {
		t.Errorf("hg-all %+v", all)
	}
	b := c.Bundles["web-1"]
	if len(b.Accounts) != 3 {
		t.Fatalf("web-1 accounts %+v", b.Accounts)
	}
	a := b.Accounts[0]
	if a.Name != "alice" || !a.Sudo || a.UID != 20001 || strings.Join(a.Principals, ",") != "up:alice@all" { // Portcullis sudo: approved principals only (RR3)
		t.Errorf("alice %+v", a)
	}
	if b.Accounts[1].Name != "bob" || b.Accounts[1].Sudo || b.Accounts[2].Name != "deploy" || b.Accounts[2].Kind != "shared" || b.Accounts[2].UID != 0 {
		t.Errorf("bob/deploy %+v", b.Accounts[1:])
	}
	golden(t, "example.roles.json", js(c.Roles))
	golden(t, "example.bundle.web-1.json", js(b))
	cfg, err := ClientConfig("example.com", c.People["alice"].HostGroups, c.Hosts)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "example.client.alice.txt", []byte(cfg))
	golden(t, "example.preview.web-1.json", js(c.Preview("web-1", false)))
	// Deterministic.
	c2 := mustCompile(t, example())
	if string(js(c2.Roles)) != string(js(c.Roles)) || BundleHash(c2.Bundles["web-1"]) != BundleHash(b) {
		t.Error("compile is not deterministic")
	}
}

func TestMergeTTLEarliestBound(t *testing.T) {
	in := example()
	// Two grants on web for alice: 2 h and 6 h; the setting is 8 h.
	in.State.Grants[0].TTLHours = 6
	in.State.Grants = append(in.State.Grants, state.SSHGrant{ID: "g-web2", Group: "ssh_admins", GroupID: 12, HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "none", TTLHours: 2, PortForwarding: true})
	c := mustCompile(t, in)
	p := c.People["alice"].HostGroups["web"]
	if !p.Until.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("until %v, want the shortest grant (2 h)", p.Until)
	}
	if strings.Join(p.Extensions, ",") != "permit-pty,permit-port-forwarding" {
		t.Errorf("extensions %v", p.Extensions)
	}
	// The setting's maximum caps a grant's TTL.
	in.State.Settings.DefaultTTLHours = 1
	c = mustCompile(t, in)
	if p := c.People["bob"].HostGroups["web"]; !p.Until.Equal(now.Add(time.Hour)) {
		t.Errorf("until %v, want the setting's 1 h", p.Until)
	}
	if c.Roles["web"].MaxTTLSeconds != 3600 {
		t.Errorf("role max %d", c.Roles["web"].MaxTTLSeconds)
	}
}

func TestMergeMembershipEndsSoon(t *testing.T) {
	in := example()
	in.Pending = map[string]map[string]time.Time{"bob": {"ssh_deploy": now.Add(20 * time.Minute)}}
	c := mustCompile(t, in)
	p := c.People["bob"].HostGroups["web"]
	if !p.Until.Equal(now.Add(20 * time.Minute)) {
		t.Errorf("until %v, want the membership's end in 20 minutes", p.Until)
	}
	rows := c.Preview("web-1", false)
	var found bool
	for _, r := range rows {
		if r.Person == "bob" && r.Account == "deploy" {
			found = r.Until != nil && r.Until.Equal(now.Add(20*time.Minute))
		}
	}
	if !found {
		t.Errorf("preview doesn't show the membership end: %+v", rows)
	}
	golden(t, "ttl.plans.bob.json", js(c.People["bob"]))
}

func TestExpiredMembershipGivesNothing(t *testing.T) {
	in := example()
	in.Expired = map[string]map[string]bool{"alice": {"ssh_admins": true}}
	in.Pending = map[string]map[string]time.Time{"bob": {"ssh_web": now.Add(-time.Second)}}
	c := mustCompile(t, in)
	if _, ok := c.People["alice"].HostGroups["all"]; ok {
		t.Error("expired membership still grants all")
	}
	if _, ok := c.Roles["all"]; ok {
		t.Error("a role without principals is kept")
	}
	if slices.Contains(c.People["bob"].HostGroups["web"].Principals, "u:bob@web") {
		t.Error("a membership whose end has passed still grants")
	}
}

func TestGroupIDMismatchGrantsNothing(t *testing.T) {
	in := example()
	in.Members["alice"]["ssh_admins"] = 99 // re-created group
	c := mustCompile(t, in)
	if _, ok := c.People["alice"].HostGroups["all"]; ok {
		t.Error("a re-created group (new id) grants")
	}
}

func TestPrivileged(t *testing.T) {
	base := state.SSHGrant{ID: "g", Group: "x", HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "none"}
	if p, _ := Privileged(base); p {
		t.Error("a plain grant is privileged")
	}
	for name, edit := range map[string]func(*state.SSHGrant){
		"sudo":           func(g *state.SSHGrant) { g.Sudo = "full" },
		"root":           func(g *state.SSHGrant) { g.Accounts = []string{"root"} },
		"agent fwd":      func(g *state.SSHGrant) { g.AgentForwarding = true },
		"shared sudo":    func(g *state.SSHGrant) { g.Accounts = []string{"deploy"}; g.Sudo = "full" },
		"all":            func(g *state.SSHGrant) { g.HostGroup = "all" },
		"portcullis-...": func(g *state.SSHGrant) { g.HostGroup = "portcullis-servers" },
		// FR-H4: a cloud image's default user (usually NOPASSWD sudo).
		"ubuntu":   func(g *state.SSHGrant) { g.Accounts = []string{"ubuntu"} },
		"ec2-user": func(g *state.SSHGrant) { g.Accounts = []string{"deploy", "ec2-user"} },
		"pi":       func(g *state.SSHGrant) { g.Accounts = []string{"pi"} },
	} {
		g := base
		g.Accounts = slices.Clone(base.Accounts)
		edit(&g)
		if p, why := Privileged(g); !p || why == "" {
			t.Errorf("%s: not privileged", name)
		}
	}
	g := base
	g.PortForwarding = true
	if p, _ := Privileged(g); p {
		t.Error("port forwarding alone is privileged")
	}
}

func TestPrivilegedDefaultTTL4h(t *testing.T) {
	s := state.SSHSettings{}
	if h := GrantTTLHours(state.SSHGrant{Sudo: "full", HostGroup: "web"}, s); h != 4 {
		t.Errorf("privileged default %d", h)
	}
	if h := GrantTTLHours(state.SSHGrant{Sudo: "none", HostGroup: "web"}, s); h != 8 {
		t.Errorf("plain default %d", h)
	}
	if h := GrantTTLHours(state.SSHGrant{Sudo: "full", HostGroup: "web", TTLHours: 10}, s); h != 8 {
		t.Errorf("a grant above the setting: %d", h)
	}
}

func TestSudoBelongsToHostAccount(t *testing.T) {
	c := mustCompile(t, example())
	for _, r := range c.Preview("web-1", false) {
		if r.Person == "alice" && r.Account == "alice" {
			if !r.Sudo || len(r.Via) != 2 {
				t.Errorf("alice on web-1 %+v", r)
			}
			return
		}
	}
	t.Error("no alice row")
}

func TestRoleDeletedWithoutGrants(t *testing.T) {
	in := example()
	in.State.Grants = in.State.Grants[:1]
	c := mustCompile(t, in)
	if _, ok := c.Roles["all"]; ok {
		t.Error("hg-all kept without grants")
	}
	if _, ok := c.Roles["web"]; !ok {
		t.Error("hg-web gone")
	}
}

func TestVPNOnlySourceAddress(t *testing.T) {
	in := example()
	g := in.State.HostGroups["web"]
	g.VPNOnly, g.VPNVia, g.SourceCIDRs = true, []string{"headscale"}, []string{"198.51.100.0/24"}
	in.State.HostGroups["web"] = g
	in.VPNRanges = func(via []string) []string {
		if !slices.Equal(via, []string{"headscale"}) {
			t.Errorf("via %v", via)
		}
		return []string{"100.64.0.0/10", "192.0.2.0/24"}
	}
	c := mustCompile(t, in)
	if got := strings.Join(c.Roles["web"].SourceAddress, ","); got != "100.64.0.0/10,192.0.2.0/24,198.51.100.0/24" {
		t.Errorf("source address %s", got)
	}
	if len(c.Roles["all"].SourceAddress) != 0 {
		t.Errorf("all source %v", c.Roles["all"].SourceAddress)
	}
}

// A username that can't be a local account (leading digit) gets no
// principal and no role entry; the bundle still lists the account (no
// principals) so the host reports ssh_host_account_invalid; the preview
// says why.
func TestUsernameNotLocalAccountStillPrincipal(t *testing.T) {
	in := example()
	in.Members["1alice"] = map[string]int{"ssh_web": 11, "ssh_deploy": 13}
	c := mustCompile(t, in)
	if slices.Contains(c.Roles["web"].Principals, "u:1alice@web") {
		t.Error("an invalid principal reached the role")
	}
	if !slices.Contains(c.People["1alice"].HostGroups["web"].Principals, "s:deploy@web") {
		t.Error("the shared account was lost too")
	}
	var acct *cliapi.Account
	for i := range c.Bundles["web-1"].Accounts {
		if c.Bundles["web-1"].Accounts[i].Name == "1alice" {
			acct = &c.Bundles["web-1"].Accounts[i]
		}
	}
	if acct == nil || len(acct.Principals) != 0 || acct.UID != 0 {
		t.Errorf("bundle entry %+v", acct)
	}
	for _, r := range c.Preview("web-1", false) {
		if r.Person == "1alice" && r.Account == "1alice" && r.Status != StatusInvalidName {
			t.Errorf("preview %+v", r)
		}
	}
}

func TestValidateRefusals(t *testing.T) {
	for name, edit := range map[string]func(*state.SSHState){
		"65th host group": func(s *state.SSHState) {
			for i := 0; len(s.HostGroups) <= 64; i++ {
				s.HostGroups[fmt.Sprintf("g%d", i)] = state.SSHHostGroup{}
			}
		},
		"portcullis-x": func(s *state.SSHState) { s.HostGroups["portcullis-x"] = state.SSHHostGroup{} },
		"{user} typo":  func(s *state.SSHState) { s.Grants[0].Accounts = []string{"{user}"} },
		"sudo some":    func(s *state.SSHState) { s.Grants[0].Sudo = "some" },
		"ttl 13":       func(s *state.SSHState) { s.Grants[0].TTLHours = 13 },
		"no all":       func(s *state.SSHState) { delete(s.HostGroups, "all") },
		"unknown hg":   func(s *state.SSHState) { s.Grants[0].HostGroup = "db" },
		"duplicate id": func(s *state.SSHState) { s.Grants[1].ID = s.Grants[0].ID },
		"bad cidr": func(s *state.SSHState) {
			g := s.HostGroups["web"]
			g.SourceCIDRs = []string{"x"}
			s.HostGroups["web"] = g
		},
		"upper hg": func(s *state.SSHState) { s.HostGroups["Web"] = state.SSHHostGroup{} },
		"257 grants": func(s *state.SSHState) {
			for len(s.Grants) <= 256 {
				g := s.Grants[0]
				g.ID = fmt.Sprintf("x%d", len(s.Grants))
				s.Grants = append(s.Grants, g)
			}
		},
		"setting 13 hours": func(s *state.SSHState) { s.Settings.DefaultTTLHours = 13 },
	} {
		in := example()
		edit(&in.State)
		if err := Validate(in.State); err == nil {
			t.Errorf("%s accepted", name)
		}
		if _, err := Compile(in); err == nil {
			t.Errorf("%s compiled", name)
		}
	}
	if err := Validate(example().State); err != nil {
		t.Errorf("example refused: %v", err)
	}
}

func TestAllocUIDNeverReuses(t *testing.T) {
	s := &state.SSHState{}
	a, _ := AllocUID(s, "alice")
	b, _ := AllocUID(s, "bob")
	if a != 20000 || b != 20001 {
		t.Fatalf("%d %d", a, b)
	}
	if again, _ := AllocUID(s, "alice"); again != a {
		t.Error("alice's uid changed")
	}
	delete(s.UIDs, "alice") // alice removed from the directory
	c, _ := AllocUID(s, "carol")
	if c != 20002 {
		t.Errorf("carol got %d: a freed uid was reused", c)
	}
	s.UIDsUsed = nil
	for u := cliapi.UIDMin; u <= cliapi.UIDMax; u++ {
		s.UIDsUsed = append(s.UIDsUsed, u)
	}
	if _, err := AllocUID(s, "dave"); !errors.Is(err, ErrNoUID) {
		t.Errorf("exhaustion: %v", err)
	}
}

func TestClientConfigExact(t *testing.T) {
	want := `# Written by portcullis login for example.com. Do not edit.
Match host web-1.example.com,web-2.example.com,10.20.0.11,10.20.0.12
  IdentityFile ~/.ssh/portcullis/example.com/id.pub
  CertificateFile ~/.ssh/portcullis/example.com/web-cert.pub
  IdentitiesOnly yes
  UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/portcullis/example.com/known_hosts
`
	got, err := ClientConfig("example.com", map[string]CertPlan{"web": {}, "empty": {}},
		map[string][]string{"web": {"web-1.example.com", "web-2.example.com", "10.20.0.11", "10.20.0.12"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestPreviewRootFilter(t *testing.T) {
	in := example()
	in.State.Grants = append(in.State.Grants, state.SSHGrant{ID: "g-root", Group: "ssh_deploy", GroupID: 13, HostGroup: "web", Accounts: []string{"root"}, Sudo: "none"})
	c := mustCompile(t, in)
	rows := c.Preview("web-1", true)
	var got []string
	for _, r := range rows {
		got = append(got, r.Person+":"+r.Account)
	}
	if strings.Join(got, ",") != "alice:alice,bob:root" {
		t.Errorf("root-only rows %v", got)
	}
	golden(t, "ceiling.bundle.web-1.json", js(c.Bundles["web-1"]))
}

func TestUnmanagedPreviewUnknown(t *testing.T) {
	in := example()
	g := in.State.HostGroups["web"]
	g.Patterns = []string{"*.lab.example.com"}
	in.State.HostGroups["web"] = g
	in.State.Hosts["lab-1"] = state.SSHHost{Names: []string{"lab-1.lab.example.com"}, HostGroups: []string{"web"}}
	c := mustCompile(t, in)
	rows := c.Preview("lab-1", false)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, r := range rows {
		if r.Status != StatusUnmanaged || r.Sudo {
			t.Errorf("unmanaged row %+v", r)
		}
	}
	if _, ok := c.Bundles["lab-1"]; ok {
		t.Error("an unmanaged entry got a bundle")
	}
	if !slices.Contains(c.Hosts["web"], "*.lab.example.com") || slices.Contains(c.Hosts["web"], "lab-1.lab.example.com") {
		t.Errorf("client names %v", c.Hosts["web"])
	}
	if strings.Join(c.Hints["web"], ",") != "s:deploy,u:alice,u:bob" {
		t.Errorf("hints %v", c.Hints["web"])
	}
	golden(t, "unmanaged.preview.lab-1.json", js(rows))
}

func TestStateSSHRoundTripInBundleOrder(t *testing.T) {
	c := mustCompile(t, example())
	b := c.Bundles["web-2"]
	raw, _ := json.Marshal(b)
	var back cliapi.Bundle
	if err := cliapi.UnmarshalStrict(raw, &back); err != nil {
		t.Fatalf("a compiled bundle fails the strict schema: %v", err)
	}
	if BundleHash(&back) != BundleHash(b) {
		t.Error("hash changes through JSON")
	}
	b2 := *b
	b2.Serial, b2.Generated = 7, now
	if BundleHash(&b2) != BundleHash(b) {
		t.Error("serial/time change the hash")
	}
	if !slices.Contains(b.Locked, "carol") && len(b.Locked) != 0 {
		t.Errorf("locked %v", b.Locked)
	}
}

func TestLockedAfterLeaving(t *testing.T) {
	in := example()
	delete(in.Members["bob"], "ssh_web")
	delete(in.Members["bob"], "ssh_deploy")
	c := mustCompile(t, in)
	b := c.Bundles["web-1"]
	if !slices.Contains(b.Locked, "bob") {
		t.Errorf("bob not locked: %v", b.Locked)
	}
	for _, a := range b.Accounts {
		if a.Name == "bob" {
			t.Error("bob still has an account")
		}
	}
}

func TestNeedUIDs(t *testing.T) {
	in := example()
	in.State.UIDs = map[string]int{"alice": 20001}
	c := mustCompile(t, in)
	if !slices.Equal(c.NeedUIDs, []string{"bob"}) {
		t.Errorf("need %v", c.NeedUIDs)
	}
	for _, a := range c.Bundles["web-1"].Accounts {
		if a.Name == "bob" {
			t.Error("bob's account without a uid")
		}
	}
}

func TestUsernameCollidesWithSharedAccount(t *testing.T) {
	in := example()
	// A person whose username is the shared account deploy, in ssh_web.
	in.Members["deploy"] = map[string]int{"ssh_web": 11}
	c := mustCompile(t, in)
	if p, ok := c.People["deploy"].HostGroups["web"]; ok {
		t.Errorf("the person deploy got %v", p.Principals)
	}
	if slices.Contains(c.Roles["web"].Principals, "u:deploy@web") {
		t.Error("u:deploy@web reached the role")
	}
	if len(c.Collisions) != 1 || c.Collisions[0].User != "deploy" || c.Collisions[0].Grant != "g-web" {
		t.Errorf("collisions %+v", c.Collisions)
	}
	for _, a := range c.Bundles["web-1"].Accounts {
		if a.Name == "deploy" && (a.Kind != "shared" || a.UID != 0 || !slices.Equal(a.Principals, []string{"s:deploy@web"})) {
			t.Errorf("deploy merged: %+v", a)
		}
	}
	var shown bool
	for _, r := range c.Preview("web-1", false) {
		if r.Person == "deploy" && strings.HasPrefix(r.Status, StatusCollision) {
			shown = true
		}
	}
	if !shown {
		t.Error("the preview doesn't show the skipped grant")
	}
}

func TestUsernameRootAndSystemSkipped(t *testing.T) {
	in := example()
	c := cliapi.DefaultCeiling()
	c.BreakglassAccount, c.ProtectedAccounts = "rescue", []string{"rescue", "ops"}
	h := in.State.Hosts["web-1"]
	h.Ceiling = &c
	in.State.Hosts["web-1"] = h
	for _, u := range []string{"root", "daemon", "www-data", "systemd-network", "_spotlight", "rescue", "ops", "admin", "portcullis-x"} {
		in.Members[u] = map[string]int{"ssh_web": 11}
	}
	got := mustCompile(t, in)
	for _, u := range []string{"root", "daemon", "www-data", "systemd-network", "rescue", "ops", "admin"} {
		if _, ok := got.People[u]; ok {
			t.Errorf("%s got a personal principal", u)
		}
	}
	if len(got.Collisions) < 7 {
		t.Errorf("collisions %+v", got.Collisions)
	}
}

func TestPrincipalNamespacesNeverOverlap(t *testing.T) {
	c := mustCompile(t, example())
	for hg, r := range c.Roles {
		for _, p := range r.Principals {
			kind, acct, g, ok := cliapi.ParsePrincipal(p)
			if !ok || g != hg {
				t.Errorf("%s: %q", hg, p)
			}
			if acct == "deploy" && kind != cliapi.PrincipalShared || acct != "deploy" && kind != cliapi.PrincipalPersonal {
				t.Errorf("%q in the wrong namespace", p)
			}
		}
	}
	for _, b := range c.Bundles {
		for _, a := range b.Accounts {
			want := cliapi.PrincipalPersonal
			if a.Kind == cliapi.AccountShared {
				want = cliapi.PrincipalShared
			}
			for _, p := range a.Principals {
				if k, acct, _, _ := cliapi.ParsePrincipal(p); k != want || acct != a.Name {
					t.Errorf("account %s carries %q", a.Name, p)
				}
			}
		}
	}
}

func TestSharedAccountEqualToUsernameRefused(t *testing.T) {
	g := state.SSHGrant{ID: "g", Group: "x", HostGroup: "web", Accounts: []string{"{username}", "alice"}, Sudo: "none"}
	if err := CheckSharedAgainstUsers(g, map[string]bool{"alice": true}); err == nil {
		t.Error("shared account alice accepted while alice is a person")
	}
	if err := CheckSharedAgainstUsers(g, map[string]bool{"bob": true}); err != nil {
		t.Error(err)
	}
}

func TestWideningReasons(t *testing.T) {
	s := state.SSHSettings{}
	base := state.SSHGrant{ID: "g", Group: "ssh_web", GroupID: 11, HostGroup: "web", Accounts: []string{"{username}", "deploy"}, Sudo: "none", TTLHours: 4}
	for name, tc := range map[string]struct {
		edit  func(*state.SSHGrant)
		widen bool
	}{
		"unchanged":        {func(*state.SSHGrant) {}, false},
		"fewer accounts":   {func(g *state.SSHGrant) { g.Accounts = []string{"deploy"} }, false},
		"shorter ttl":      {func(g *state.SSHGrant) { g.TTLHours = 2 }, false},
		"new account":      {func(g *state.SSHGrant) { g.Accounts = append(g.Accounts, "backup") }, true},
		"swap account":     {func(g *state.SSHGrant) { g.Accounts = []string{"{username}", "backup"} }, true},
		"longer ttl":       {func(g *state.SSHGrant) { g.TTLHours = 6 }, true},
		"ttl to default":   {func(g *state.SSHGrant) { g.TTLHours = 0 }, true}, // 8 h > 4 h
		"port forwarding":  {func(g *state.SSHGrant) { g.PortForwarding = true }, true},
		"agent forwarding": {func(g *state.SSHGrant) { g.AgentForwarding = true }, true},
		"sudo":             {func(g *state.SSHGrant) { g.Sudo = "full" }, true},
		"root":             {func(g *state.SSHGrant) { g.Accounts = append(g.Accounts, "root") }, true},
		"host group":       {func(g *state.SSHGrant) { g.HostGroup = "db" }, true},
		"to all":           {func(g *state.SSHGrant) { g.HostGroup = "all" }, true},
		"group":            {func(g *state.SSHGrant) { g.Group = "ssh_other" }, true},
		"group id":         {func(g *state.SSHGrant) { g.GroupID = 12 }, true},
	} {
		after := base
		after.Accounts = slices.Clone(base.Accounts)
		tc.edit(&after)
		b := base
		if got := Widens(&b, after, s); got != tc.widen {
			t.Errorf("%s: widens %v (%v)", name, got, WideningReasons(&b, after, s))
		}
	}
	if Widens(nil, base, s) {
		t.Error("a new grant is judged by Privileged, not Widens")
	}
}
