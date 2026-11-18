package state

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

func TestStateSSHRoundTrip(t *testing.T) {
	s := New()
	if _, ok := s.SSH.HostGroups["all"]; !ok {
		t.Fatal("New has no built-in all host group")
	}
	if s.SSH.Settings.Enabled {
		t.Fatal("SSH access starts on")
	}
	c := cliapi.DefaultCeiling()
	s.SSH.Settings = SSHSettings{Enabled: true, DefaultTTLHours: 6}
	s.SSH.HostGroups["web"] = SSHHostGroup{Label: "Web", Template: "standard", Patterns: []string{"*.lab.example.com"}, SourceCIDRs: []string{"192.0.2.0/24"}, VPNOnly: true, VPNVia: []string{"headscale"}, NoHostCerts: true, Delegable: true, CreateShared: true}
	s.SSH.Hosts = map[string]SSHHost{"web-1": {Names: []string{"web-1.example.com"}, Addrs: []string{"192.0.2.11"}, HostGroups: []string{"web"}, Managed: true,
		KeyFP: "SHA256:x", HostKey: "ssh-ed25519 AAAA", EnrolHash: "ab", EnrolExpires: time.Date(2026, 11, 15, 9, 15, 0, 0, time.UTC), Serial: 3,
		HostCert: "ssh-ed25519-cert-v01@openssh.com AAAA", HostCertUntil: time.Date(2027, 2, 13, 9, 0, 0, 0, time.UTC), Ceiling: &c, RemoveAccounts: []string{"carol"},
		LastSync: time.Date(2026, 11, 15, 9, 1, 0, 0, time.UTC)}}
	s.SSH.Grants = []SSHGrant{{ID: "g1", Group: "ssh_web", GroupID: 11, HostGroup: "web", Accounts: []string{"{username}", "deploy"}, Sudo: SudoFull, TTLHours: 4, PortForwarding: true, AgentForwarding: true}}
	s.SSH.UIDs = map[string]int{"alice": 20000}
	s.SSH.UIDsUsed = []int{20000, 20001}
	s.SSH.Serial = 9
	p := filepath.Join(t.TempDir(), "state.yaml")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.SSH, s.SSH) {
		raw, _ := os.ReadFile(p)
		t.Errorf("round trip differs:\n%+v\n%+v\n%s", back.SSH, s.SSH, raw)
	}
	if back.SSH.HostGroups["web"].HostCerts() || back.SSH.HostGroups["web"].GoverningTemplate() != "standard" || back.SSH.HostGroups["all"].GoverningTemplate() != "strong" {
		t.Error("helpers")
	}
	if back.SSH.Settings.TTLHours() != 6 || (SSHSettings{}).TTLHours() != 8 {
		t.Error("TTLHours")
	}
}
