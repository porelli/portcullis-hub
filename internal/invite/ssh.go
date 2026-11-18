package invite

// enroll's SSH endpoints (contract §18.8): the per-host-group Vault roles,
// user and host certificate signing, and the CA public keys. Same listener
// and bearer as the certificate actions. Public keys and certificates
// cross this client; private keys never do. Nothing here logs a key.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

// SSHOpTimeout bounds every SSH call (contract §9.4 certOpTimeout).
const SSHOpTimeout = 15 * time.Second

// SSHUserSign asks enroll for one user certificate.
type SSHUserSign struct {
	User         string   `json:"user"`
	HostGroup    string   `json:"host_group"`
	PublicKey    string   `json:"public_key"`
	Principals   []string `json:"principals"`
	ValidSeconds int      `json:"valid_seconds"`
	Extensions   []string `json:"extensions"`
	KeyID        string   `json:"key_id"`
}

// SSHHostSign asks enroll for one host certificate.
type SSHHostSign struct {
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals"`
	HostGroup  string   `json:"host_group"`
	HostID     string   `json:"host_id"`
}

// SSHSigned is a signed certificate (public).
type SSHSigned struct {
	Certificate string    `json:"certificate"`
	Serial      string    `json:"serial"`
	ValidBefore time.Time `json:"valid_before"`
}

// String names the certificate by serial only.
func (s SSHSigned) String() string {
	return fmt.Sprintf("ssh certificate %s (until %s)", s.Serial, s.ValidBefore.UTC().Format(time.RFC3339))
}

// SSHCA is GET /internal/ssh-ca.
type SSHCA struct {
	UserCAs  []string `json:"user_cas"`
	HostCAs  []string `json:"host_cas"`
	Problems []string `json:"problems"`
}

func roleID(hg string) (string, error) {
	if !cliapi.ValidHostGroupID(hg) || cliapi.ReservedHostGroupID(hg) {
		return "", &APIError{Status: http.StatusBadRequest, Message: "invalid host group id"}
	}
	return "ssh-roles/" + url.PathEscape(hg), nil
}

// PutSSHRole writes host group hg's role (PUT /internal/ssh-roles/{hg})
// and returns it as Vault reads it back.
func (c *Client) PutSSHRole(ctx context.Context, hg string, r cliapi.RoleSpec) (*cliapi.RoleSpec, error) {
	p, err := roleID(hg)
	if err != nil {
		return nil, err
	}
	if r.Principals == nil {
		r.Principals = []string{}
	}
	if r.SourceAddress == nil {
		r.SourceAddress = []string{}
	}
	ctx, cancel := context.WithTimeout(ctx, SSHOpTimeout)
	defer cancel()
	data, err := c.send(ctx, http.MethodPut, p, r, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var back cliapi.RoleSpec
	if !decodeOne(data, &back) {
		return nil, errors.New("ssh roles API: malformed answer")
	}
	return &back, nil
}

// DeleteSSHRole deletes host group hg's role (204; a missing role too).
func (c *Client) DeleteSSHRole(ctx context.Context, hg string) error {
	p, err := roleID(hg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, SSHOpTimeout)
	defer cancel()
	_, err = c.send(ctx, http.MethodDelete, p, nil, http.StatusNoContent)
	return err
}

// ListSSHRoles lists the host groups that have a role (GET
// /internal/ssh-roles: role names hg-<id>, returned as the ids).
func (c *Client) ListSSHRoles(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, SSHOpTimeout)
	defer cancel()
	data, err := c.send(ctx, http.MethodGet, "ssh-roles", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Roles []string `json:"roles"`
	}
	if !decodeOne(data, &doc) {
		return nil, errors.New("ssh roles API: malformed answer")
	}
	out := []string{}
	for _, r := range doc.Roles {
		hg, ok := strings.CutPrefix(r, "hg-")
		if !ok || !cliapi.ValidHostGroupID(hg) {
			continue // never ours to delete
		}
		out = append(out, hg)
	}
	return out, nil
}

// SignSSHUser asks enroll for a user certificate (POST
// /internal/ssh-certificates → 201). Protected names never reach enroll.
func (c *Client) SignSSHUser(ctx context.Context, r SSHUserSign) (*SSHSigned, error) {
	if ProtectedName(r.User) {
		return nil, errProtected()
	}
	ctx, cancel := context.WithTimeout(ctx, SSHOpTimeout)
	defer cancel()
	return c.signed(ctx, "ssh-certificates", r)
}

// SignSSHHost asks enroll for a host certificate (POST
// /internal/ssh-host-certificates → 201).
func (c *Client) SignSSHHost(ctx context.Context, r SSHHostSign) (*SSHSigned, error) {
	ctx, cancel := context.WithTimeout(ctx, SSHOpTimeout)
	defer cancel()
	return c.signed(ctx, "ssh-host-certificates", r)
}

func (c *Client) signed(ctx context.Context, path string, body any) (*SSHSigned, error) {
	data, err := c.post(ctx, path, body, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var s SSHSigned
	if !decodeOne(data, &s) || s.Certificate == "" || s.Serial == "" || s.ValidBefore.IsZero() {
		return nil, errors.New("ssh certificates API: malformed answer")
	}
	return &s, nil
}

// SSHCA reads the CA public keys and the §18.7 differences enroll sees.
func (c *Client) SSHCA(ctx context.Context) (*SSHCA, error) {
	ctx, cancel := context.WithTimeout(ctx, SSHOpTimeout)
	defer cancel()
	data, err := c.send(ctx, http.MethodGet, "ssh-ca", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var ca SSHCA
	if !decodeOne(data, &ca) {
		return nil, errors.New("ssh CA API: malformed answer")
	}
	return &ca, nil
}
