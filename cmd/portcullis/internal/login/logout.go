package login

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/cmd/portcullis/internal/agentx"
	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/config"
	"github.com/portcullis/hub/cmd/portcullis/internal/sshconf"
	"github.com/portcullis/hub/internal/cliapi"
)

// Logout removes domain's Portcullis keys from the agent and its files;
// revoke first revokes this login's keys (a fresh sign-in).
func Logout(ctx context.Context, o Options, revoke bool) error {
	o.defaults()
	if !cliapi.ValidDomain(o.Domain) {
		return api.Errorf(api.ExitUsage, "not a domain")
	}
	var keys []string
	if raw, err := os.ReadFile(filepath.Join(sshconf.Dir(o.Home, o.Domain), "id.pub")); err == nil {
		if _, norm, err := cliapi.ParseAuthorizedKey(strings.TrimSpace(string(raw))); err == nil {
			keys = append(keys, norm)
		}
	}
	ag, closeAg, aerr := o.Agent()
	if aerr == nil {
		defer closeAg()
		if l, err := agentx.List(ag); err == nil {
			for _, k := range l {
				if k.Domain == o.Domain {
					keys = append(keys, cliapi.NormalAuthorizedKey(k.Certificate.Key))
				}
			}
		}
	}
	if revoke && len(keys) > 0 {
		f, err := config.Load(o.ConfigDir)
		if err != nil {
			return err
		}
		caFile := o.CAFile
		if caFile == "" {
			caFile = f.Domains[o.Domain].CAFile
		}
		c, err := o.Client(caFile)
		if err != nil {
			return err
		}
		cfg, err := Discover(ctx, &o, c)
		if err != nil {
			return err
		}
		si, err := DoSignIn(ctx, &o, cfg)
		if err != nil {
			return err
		}
		var ans cliapi.RevocationAnswer
		req := cliapi.RevocationRequest{Code: si.Code, CodeVerifier: si.Verifier, Nonce: si.Nonce, RedirectURI: si.RedirectURI, PublicKeys: dedup(keys)}
		if _, err := c.Do(ctx, http.MethodPost, "/api/cli/v1/ssh/revocations", req, &ans, nil); err != nil {
			return err
		}
		fmt.Fprintf(o.Stdout, "Revoked %d key(s): managed hosts refuse them within seconds.\n", ans.Revoked)
	}
	if aerr == nil {
		n, _ := agentx.RemoveDomain(ag, o.Domain)
		fmt.Fprintf(o.Stdout, "Removed %d key(s) from your ssh-agent.\n", n)
	}
	return sshconf.Remove(o.Home, o.Domain)
}

func dedup(s []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range s {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// Status prints the agent's Portcullis certificates and the written
// certificate files (no network).
func Status(o Options) error {
	o.defaults()
	now := o.Now()
	found := false
	if ag, closeAg, err := o.Agent(); err == nil {
		defer closeAg()
		l, _ := agentx.List(ag)
		for _, k := range l {
			found = true
			fmt.Fprintf(o.Stdout, "agent  %-20s %-10s %s  %s  until %s%s\n", k.Domain, k.HostGroup, k.KeyType,
				strings.Join(k.Certificate.ValidPrincipals, ","), time.Unix(int64(k.Certificate.ValidBefore), 0).Local().Format("Mon 02 Jan 15:04"), expired(k.Certificate.ValidBefore, now))
		}
	} else {
		fmt.Fprintln(o.Stderr, "No ssh-agent: only the written files are listed.")
	}
	files, _ := filepath.Glob(filepath.Join(o.Home, ".ssh", "portcullis", "*", "*-cert.pub"))
	sort.Strings(files)
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		c, err := sshconf.ParseCert(strings.TrimSpace(string(raw)))
		if err != nil {
			continue
		}
		found = true
		fmt.Fprintf(o.Stdout, "file   %-20s %-10s %s  %s  until %s%s\n", filepath.Base(filepath.Dir(p)), strings.TrimSuffix(filepath.Base(p), "-cert.pub"), c.Key.Type(),
			strings.Join(c.ValidPrincipals, ","), time.Unix(int64(c.ValidBefore), 0).Local().Format("Mon 02 Jan 15:04"), expired(c.ValidBefore, now))
	}
	if !found {
		fmt.Fprintln(o.Stdout, "No Portcullis SSH certificates: run portcullis login <domain>.")
	}
	return nil
}

func expired(vb uint64, now time.Time) string {
	if time.Unix(int64(vb), 0).Before(now) {
		return " (expired)"
	}
	return ""
}
