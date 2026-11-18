package invite

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

func TestPutSSHRoleBody(t *testing.T) {
	f, c := newFakeEnroll(t)
	f.status = 200
	f.body = `{"principals":["u:alice@web"],"extensions":"permit-pty","source_address":[],"max_ttl_s":28800}`
	back, err := c.PutSSHRole(context.Background(), "web", cliapi.RoleSpec{Principals: []string{"u:alice@web"}, Extensions: "permit-pty", MaxTTLSeconds: 28800})
	if err != nil {
		t.Fatal(err)
	}
	if f.method != http.MethodPut || f.path != "/internal/ssh-roles/web" || f.auth != "Bearer "+f.secret || f.ctype != "application/json" {
		t.Errorf("request %s %s auth %q type %q", f.method, f.path, f.auth, f.ctype)
	}
	if f.req != `{"principals":["u:alice@web"],"extensions":"permit-pty","source_address":[],"max_ttl_s":28800}` {
		t.Errorf("body %s", f.req)
	}
	if back.MaxTTLSeconds != 28800 || back.Principals[0] != "u:alice@web" {
		t.Errorf("read-back %+v", back)
	}
	// Errors map like the certificate actions: enroll's text for 400.
	f.status, f.body = 400, `{"error":"principal outside the grammar"}`
	_, err = c.PutSSHRole(context.Background(), "web", cliapi.RoleSpec{})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 || ae.Message != "principal outside the grammar" {
		t.Errorf("400 = %v", err)
	}
	// An answer with an unknown field is refused.
	f.status, f.body = 200, `{"principals":[],"extensions":"permit-pty","source_address":[],"max_ttl_s":3600,"x":1}`
	if _, err := c.PutSSHRole(context.Background(), "web", cliapi.RoleSpec{}); err == nil {
		t.Error("a malformed read-back accepted")
	}
	// Bad ids never reach enroll.
	calls := f.calls
	for _, bad := range []string{"portcullis-servers", "Web", "../x", ""} {
		if _, err := c.PutSSHRole(context.Background(), bad, cliapi.RoleSpec{}); err == nil {
			t.Errorf("%q accepted", bad)
		}
		if err := c.DeleteSSHRole(context.Background(), bad); err == nil {
			t.Errorf("delete %q accepted", bad)
		}
	}
	if f.calls != calls {
		t.Error("a bad id reached enroll")
	}
}

func TestDeleteAndListSSHRoles(t *testing.T) {
	f, c := newFakeEnroll(t)
	f.status = 204
	if err := c.DeleteSSHRole(context.Background(), "web"); err != nil || f.method != http.MethodDelete || f.path != "/internal/ssh-roles/web" || f.req != "" {
		t.Errorf("delete: %v %s %s %q", err, f.method, f.path, f.req)
	}
	f.status, f.body = 200, `{"roles":["hg-web","hg-all","client-cert","hg-Bad"]}`
	got, err := c.ListSSHRoles(context.Background())
	if err != nil || strings.Join(got, ",") != "web,all" || f.method != http.MethodGet {
		t.Errorf("list %v %v", got, err)
	}
}

func TestSignSSHUserNeverLogsKey(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)
	f, c := newFakeEnroll(t)
	f.status = 201
	f.body = `{"certificate":"ssh-ed25519-cert-v01@openssh.com AAAAC3cert","serial":"42","valid_before":"2026-11-15T17:00:00Z"}`
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXf2yZXNFwHqiadxQBruvDLwOZYX4l4+MUIDqyknOMZ"
	s, err := c.SignSSHUser(context.Background(), SSHUserSign{User: "alice", HostGroup: "web", PublicKey: key, Principals: []string{"u:alice@web"}, ValidSeconds: 3600, Extensions: []string{"permit-pty"}, KeyID: "pc:alice:web:0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Serial != "42" || !s.ValidBefore.Equal(time.Date(2026, 11, 15, 17, 0, 0, 0, time.UTC)) || f.path != "/internal/ssh-certificates" {
		t.Errorf("signed %+v path %s", s, f.path)
	}
	if strings.Contains(s.String(), "AAAA") {
		t.Error("String prints the certificate")
	}
	f.status, f.body = 409, `{"error":"protected account"}`
	if _, err := c.SignSSHUser(context.Background(), SSHUserSign{User: "bob", PublicKey: key}); err == nil || strings.Contains(err.Error(), "AAAA") {
		t.Errorf("409 = %v", err)
	}
	calls := f.calls
	if _, err := c.SignSSHUser(context.Background(), SSHUserSign{User: "portcullis-hub", PublicKey: key}); err == nil || f.calls != calls {
		t.Error("a protected name reached enroll")
	}
	if strings.Contains(buf.String(), "AAAA") {
		t.Errorf("a key reached the log: %s", buf.String())
	}
}

func TestSignSSHHostAndCA(t *testing.T) {
	f, c := newFakeEnroll(t)
	f.status = 201
	f.body = `{"certificate":"ssh-ed25519-cert-v01@openssh.com AAAA","serial":"7","valid_before":"2027-02-13T09:00:00Z"}`
	if _, err := c.SignSSHHost(context.Background(), SSHHostSign{PublicKey: "ssh-ed25519 AAAA", Principals: []string{"web-1.example.com"}, HostGroup: "web", HostID: "web-1"}); err != nil {
		t.Fatal(err)
	}
	if f.path != "/internal/ssh-host-certificates" || !strings.Contains(f.req, `"host_id":"web-1"`) {
		t.Errorf("host sign %s %s", f.path, f.req)
	}
	f.status, f.body = 200, `{"user_cas":["ssh-ed25519 AAAA"],"host_cas":["ssh-ed25519 BBBB"],"problems":[]}`
	ca, err := c.SSHCA(context.Background())
	if err != nil || len(ca.UserCAs) != 1 || f.method != http.MethodGet || f.path != "/internal/ssh-ca" {
		t.Errorf("ca %+v %v", ca, err)
	}
	f.body = `{"user_cas":[]}`
	if _, err := c.SSHCA(context.Background()); err != nil {
		t.Errorf("a partial CA answer: %v", err)
	}
	f.status, f.body = 201, `{"certificate":"","serial":"","valid_before":"0001-01-01T00:00:00Z"}`
	if _, err := c.SignSSHHost(context.Background(), SSHHostSign{}); err == nil {
		t.Error("an empty certificate accepted")
	}
}
