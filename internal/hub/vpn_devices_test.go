package hub

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/state"
)

// vpnFresh is the VPN page's fake verifier: proof "ok" passes for the
// caller, "old" is a sign-in older than 5 min, "bob" is bob's proof.
type vpnFresh struct{ now func() time.Time }

func (f *vpnFresh) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	switch p.Code {
	case "ok":
		return &freshauth.Result{User: user, AuthTime: f.now(), Method: "security_key"}, nil
	case "old":
		return &freshauth.Result{User: user, AuthTime: f.now().Add(-6 * time.Minute), Method: "security_key"}, nil
	case "bob":
		return &freshauth.Result{User: "bob", AuthTime: f.now(), Method: "security_key"}, nil
	}
	return nil, &freshauth.Error{Reason: "bad code"}
}

func (f *vpnFresh) Info() freshauth.AuthorizeInfo {
	return freshauth.AuthorizeInfo{AuthorizeURL: "https://auth.example.org/a", ClientID: freshauth.ClientID, RedirectURI: "https://people.example.org/vpn/"}
}

var okProof = freshauth.Proof{Code: "ok", CodeVerifier: "v", Nonce: "n"}

func newDeviceFixture(t *testing.T, seed func(*state.AppState)) *vpnFixture {
	t.Helper()
	v := newVPNFixture(t, seed)
	v.h.SetFreshAuth(ListenerPeopleVPN, &vpnFresh{now: v.clock})
	v.h.SetFreshAuthReadyForTest(true)
	return v
}

func statusCode(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

func TestAddDeviceNeedsFreshAuth(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	for _, p := range []freshauth.Proof{{}, {Code: "old"}, {Code: "bob"}, {Code: "nope"}} {
		if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), p); statusCode(err) != 403 {
			t.Errorf("proof %q: %v", p.Code, err)
		}
	}
	cfg, err := v.h.AddVPNDevice(ctx, "Alice", "laptop", keyOf(2), okProof)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowedIPs != "10.213.0.1/32" || cfg.DNS != "10.213.0.1" || cfg.MTU != 1280 || cfg.Endpoint != "example.org:51820" ||
		cfg.Address != "10.213.0.2" || cfg.ServerPublicKey != vpnServerKey {
		t.Fatalf("%+v", cfg)
	}
	d := v.doc(t)
	if dv, ok := d.Lookup("builtin", netip.MustParseAddr("10.213.0.2"), v.clock()); !ok || dv.User != "alice" {
		t.Fatalf("vpn.json: %+v", d)
	}
	var added int
	for _, e := range v.audit.entries {
		if e.Action == "vpn.device_added" {
			if strings.Contains(e.Detail+e.Target+e.Error, keyOf(2)) {
				t.Errorf("audit holds the key: %+v", e)
			}
			if e.Result == "ok" {
				added++
			}
		}
	}
	if added != 1 {
		t.Fatalf("%d vpn.device_added ok entries", added)
	}
}

func TestAddDeviceRefusals(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", "not-a-key", okProof); statusCode(err) != 400 {
		t.Errorf("bad key: %v", err)
	}
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	if _, err := v.h.AddVPNDevice(ctx, "bob", "phone", keyOf(2), okProof); statusCode(err) != 409 {
		t.Errorf("key in use: %v", err)
	}
	for i := 3; i < 12; i++ {
		if _, err := v.h.AddVPNDevice(ctx, "alice", "d", keyOf(byte(i)), okProof); err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	if _, err := v.h.AddVPNDevice(ctx, "alice", "d11", keyOf(20), okProof); statusCode(err) != 409 || !strings.Contains(err.Error(), "at most 10 devices") {
		t.Errorf("11th: %v", err)
	}
	v.h.mu.Lock()
	v.h.st.VPN.UsersGroup = "vpn_users"
	v.h.mu.Unlock()
	if _, err := v.h.AddVPNDevice(ctx, "bob", "phone", keyOf(21), okProof); statusCode(err) != 403 {
		t.Errorf("outside the group: %v", err)
	}
	v.h.mu.Lock()
	v.h.st.VPN.UsersGroup = ""
	v.h.st.VPN.BuiltinOff = true
	v.h.mu.Unlock()
	if _, err := v.h.AddVPNDevice(ctx, "bob", "phone", keyOf(22), okProof); statusCode(err) != 409 {
		t.Errorf("builtin off: %v", err)
	}
}

func TestRemoveQuarantinesAddress(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	id := v.h.VPNDevices(ctx, "alice")[0].ID
	if err := v.h.RemoveVPNDevice(ctx, root, id); err != nil {
		t.Fatal(err)
	}
	cfg, _ := v.h.AddVPNDevice(ctx, "alice", "phone", keyOf(3), okProof)
	if cfg.Address == "10.213.0.2" {
		t.Fatal("a removed address was handed out at once")
	}
	v.advance(8 * 24 * time.Hour)
	v.writeStatus(t, true)
	cfg, _ = v.h.AddVPNDevice(ctx, "alice", "tablet", keyOf(4), okProof)
	if cfg == nil || cfg.Address != "10.213.0.2" {
		t.Fatalf("after 8 days: %+v", cfg)
	}
}

func TestRecreatedPersonDoesNotInheritDevices(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	v.people.recreate("alice")
	v.h.TriggerVPNPublish()
	if d := v.doc(t); len(d.Devices) != 0 {
		t.Fatalf("re-created alice's device still published: %+v", d.Devices)
	}
	v.h.vpnExpireOnce(ctx)
	if n := len(v.h.VPNDevices(ctx, "alice")); n != 0 {
		t.Fatalf("%d devices left", n)
	}
	found := false
	for _, e := range v.audit.entries {
		if e.Action == "vpn.device_removed" && strings.Contains(e.Detail, "reason=account re-created") {
			found = true
		}
	}
	if !found {
		t.Fatal("no vpn.device_removed (account re-created)")
	}
}

func TestGroupLeaveRevokes(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	v.people.addGroup("vpn_users", "alice")
	v.h.mu.Lock()
	v.h.st.VPN.UsersGroup = "vpn_users"
	v.h.mu.Unlock()
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	v.people.removeMember("vpn_users", "alice")
	v.h.vpnExpireOnce(ctx)
	if n := len(v.h.VPNDevices(ctx, "alice")); n != 0 {
		t.Fatalf("%d devices after leaving the group", n)
	}
}

func TestDisableRemovesDevices(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	v.people.set(func(p *fakePeople) { delete(p.users, "alice") })
	v.h.vpnExpireOnce(ctx)
	if n := len(v.h.VPNDevices(ctx, "alice")); n != 0 {
		t.Fatalf("%d devices after the person went", n)
	}
}

func TestExpiryAudited(t *testing.T) {
	v := newDeviceFixture(t, func(st *state.AppState) { st.VPN.Expiry = "30d" })
	ctx := context.Background()
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	v.advance(31 * 24 * time.Hour)
	v.writeStatus(t, true)
	v.h.vpnExpireOnce(ctx)
	if n := len(v.h.VPNDevices(ctx, "alice")); n != 0 {
		t.Fatal("expired device kept")
	}
	ok := false
	for _, e := range v.audit.entries {
		if e.Action == "vpn.device_expired" && e.Result == "ok" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("no vpn.device_expired")
	}
}

func TestRenewRekeys(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	id := v.h.VPNDevices(ctx, "alice")[0].ID
	if _, err := v.h.RenewVPNDevice(ctx, "alice", id, keyOf(5), freshauth.Proof{Code: "old"}); statusCode(err) != 403 {
		t.Fatalf("old proof: %v", err)
	}
	if _, err := v.h.RenewVPNDevice(ctx, "bob", id, keyOf(5), okProof); statusCode(err) != 404 {
		t.Fatalf("another person's: %v", err)
	}
	cfg, err := v.h.RenewVPNDevice(ctx, "alice", id, keyOf(5), okProof)
	if err != nil || cfg.Address != "10.213.0.2" {
		t.Fatalf("%+v %v", cfg, err)
	}
	v.h.mu.RLock()
	d := v.h.st.VPN.Devices[0]
	v.h.mu.RUnlock()
	if d.ID != id || d.PublicKey != keyOf(5) || d.IP != "10.213.0.2" {
		t.Fatalf("%+v", d)
	}
}

func TestPeopleVPNDevicesAdminOnly(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	v.h.SetSignInHelp(&fakeHelp{admins: map[string]bool{"root": true}})
	if _, err := v.h.AddVPNDevice(ctx, "alice", "laptop", keyOf(2), okProof); err != nil {
		t.Fatal(err)
	}
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1", hookDev("7", "100.64.0.7", "sub-alice"))
	v.h.runVPNProvider(ctx, "mesh")
	admin := &directory.Caller{User: "root", Admin: true}
	holder := &directory.Caller{User: "carol", Perms: map[string]bool{directory.PermSignInHelp: true}}
	other := &directory.Caller{User: "bob"}
	for _, c := range []*directory.Caller{admin, holder} {
		devs, err := v.h.PersonVPNDevices(ctx, c, "alice")
		if err != nil || len(devs) != 2 {
			t.Fatalf("%s: %+v %v", c.User, devs, err)
		}
	}
	if _, err := v.h.PersonVPNDevices(ctx, other, "alice"); statusCode(err) != 403 {
		t.Fatalf("another person: %v", err)
	}
	if err := v.h.RemovePersonVPNDevice(ctx, other, "alice", "x"); statusCode(err) != 403 {
		t.Fatalf("another person removes: %v", err)
	}
	if err := v.h.RemovePersonVPNDevice(ctx, holder, "alice", "mesh:7"); statusCode(err) != 409 || !strings.Contains(err.Error(), "managed in Mesh tailnet") {
		t.Fatalf("marketplace device: %v", err)
	}
	id := v.h.VPNDevices(ctx, "alice")[0].ID
	if err := v.h.RemovePersonVPNDevice(ctx, holder, "bob", id); statusCode(err) != 404 {
		t.Fatalf("someone else's id: %v", err)
	}
	if err := v.h.RemovePersonVPNDevice(ctx, holder, "alice", id); err != nil {
		t.Fatal(err)
	}
	if devs := v.h.VPNDevices(ctx, "alice"); len(devs) != 1 || devs[0].Managed {
		t.Fatalf("%+v", devs)
	}
}

func TestHostAddVPNDevice(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	cfg, err := v.h.HostAddVPNDevice(ctx, "Carol", "desk", keyOf(9))
	if err != nil || cfg.Address != "10.213.0.2" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := v.h.HostAddVPNDevice(ctx, "dave", "desk", keyOf(10)); statusCode(err) != 403 {
		t.Fatalf("not a person: %v", err)
	}
	var actor string
	for _, e := range v.audit.entries {
		if e.Action == "vpn.device_added" && e.Result == "ok" {
			actor = e.Actor
		}
	}
	if actor != HostActor {
		t.Fatalf("audit actor %q", actor)
	}
	if l := v.h.HostVPNDevices(ctx, ""); len(l) != 1 || l[0].User != "carol" {
		t.Fatalf("%+v", l)
	}
	info := v.h.VPNHostInfo(ctx)
	if len(info.ProviderRanges) != 1 || info.ProviderRanges[0] != "10.213.0.0/22" || info.AdminDeviceSeen {
		t.Fatalf("%+v", info)
	}
}

// The lock-out guard: an lldap_admin member's device with a handshake in
// the last 10 minutes, on the built-in provider (or a hook map).
func TestVPNHostInfoAdminDeviceSeen(t *testing.T) {
	v := newDeviceFixture(t, nil)
	ctx := context.Background()
	if _, err := v.h.HostAddVPNDevice(ctx, "root", "laptop", keyOf(9)); err != nil {
		t.Fatal(err)
	}
	write := func(at time.Time) {
		b := `{"version":1,"written":"` + v.clock().Format(time.RFC3339) + `","mode":"apps","edge":{"ok":true,"error":""},"people":{"ok":true,"error":"","public_key":"` + vpnServerKey +
			`","port":51820,"subnet":"10.213.0.0/22","mtu":1280,"peers":[{"public_key":"` + keyOf(9) + `","last_handshake":"` + at.Format(time.RFC3339) + `"}]}}`
		writeFile(t, v.status, b)
	}
	write(v.clock().Add(-9 * time.Minute))
	if !v.h.VPNHostInfo(ctx).AdminDeviceSeen {
		t.Fatal("admin seen 9 min ago")
	}
	write(v.clock().Add(-11 * time.Minute))
	if v.h.VPNHostInfo(ctx).AdminDeviceSeen {
		t.Fatal("admin seen 11 min ago counted")
	}
	// A non-admin's recent device doesn't count.
	v2 := newDeviceFixture(t, nil)
	v2.h.HostAddVPNDevice(ctx, "alice", "laptop", keyOf(9))
	v = v2
	write(v.clock())
	if v.h.VPNHostInfo(ctx).AdminDeviceSeen {
		t.Fatal("a non-admin counted")
	}
}
