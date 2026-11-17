package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/host"
	"github.com/portcullis/hub/internal/cliapi"
)

// hostCmd is `portcullis host …` (contract §18.11, §18.14; needs root).
func hostCmd() *cobra.Command {
	h := &cobra.Command{Use: "host", Short: "Set up and keep a host trusting Portcullis certificates (needs root)"}
	h.AddCommand(trustCmd(), revokedKeysCmd())
	addHostCommands(h)
	return h
}

// fetcher GETs public CLI paths on https://people.<domain>.
func fetcher(domain, caFile string) func(context.Context, string) ([]byte, error) {
	return func(ctx context.Context, path string) ([]byte, error) {
		if caFile != "" {
			if err := host.CheckRootFile(host.OS{}, caFile); err != nil {
				return nil, err
			}
		}
		c, err := api.New("https://people."+domain, version, caFile)
		if err != nil {
			return nil, err
		}
		return c.Get(ctx, path)
	}
}

func needRoot() error {
	if runtime.GOOS == "windows" {
		return api.Errorf(api.ExitUsage, "Windows hosts: follow the manual steps in the docs")
	}
	if os.Geteuid() != 0 {
		return api.Errorf(api.ExitUsage, "run this as root (sudo portcullis host …)")
	}
	return nil
}

func trustCmd() *cobra.Command {
	var o host.TrustOptions
	var caFile string
	c := &cobra.Command{Use: "trust", Short: "Unmanaged host: trust the Portcullis user CA (no connection unless --ca-fingerprint or --revoked-keys)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := needRoot(); err != nil {
				return err
			}
			o.Domain = strings.ToLower(o.Domain)
			if o.CAFingerprint != "" || o.RevokedKeys {
				o.Fetch = fetcher(o.Domain, caFile)
			}
			if self, err := os.Executable(); err == nil {
				o.Self = self
			}
			if err := host.Trust(cmd.Context(), host.OS{}, o); err != nil {
				return api.Errorf(api.ExitError, "%v", err)
			}
			if o.RevokedKeys && caFile != "" {
				_ = host.SaveRevokedCAFile(host.OS{}, caFile)
			}
			fmt.Println("This host now trusts Portcullis certificates for host group " + o.HostGroup + ".")
			return nil
		}}
	f := c.Flags()
	f.StringVar(&o.Domain, "domain", "", "the Portcullis domain")
	f.StringVar(&o.HostGroup, "host-group", "", "the host group this host belongs to")
	f.StringVar(&o.CAKey, "ca-key", "", "the user CA's public key line (from the Hub's host group page)")
	f.StringVar(&o.CAFingerprint, "ca-fingerprint", "", "fetch the CA key and accept it only with this fingerprint (SHA256:…)")
	f.StringSliceVar(&o.Persons, "person", nil, "a person's own account (repeatable)")
	f.StringSliceVar(&o.Accounts, "account", nil, "a shared account (repeatable)")
	f.BoolVar(&o.RevokedKeys, "revoked-keys", false, "pull the revoked keys every 5 minutes")
	f.StringVar(&o.Breakglass, "breakglass-account", cliapi.DefaultBreakglassAccount, "the account with its own authorized_keys that keeps working without Portcullis")
	f.BoolVar(&o.NoBreakglass, "no-breakglass-i-have-console-access", false, "no break-glass account: you have console access")
	f.BoolVar(&o.ServiceNone, "service-none", false, "don't use systemd / launchd (containers): reload sshd by its pid file")
	f.StringVar(&caFile, "ca-file", "", "trust an extra CA for the fetches (a test server's staging root)")
	return c
}

func revokedKeysCmd() *cobra.Command {
	return &cobra.Command{Use: "revoked-keys", Short: "Fetch the public revoked-keys list (the 5-minute timer)", Args: cobra.NoArgs, Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, caFile, err := host.RevokedDomain(host.OS{})
			if err != nil {
				return api.Errorf(api.ExitError, "%v", err)
			}
			if err := host.FetchRevokedKeys(cmd.Context(), host.OS{}, fetcher(d, caFile)); err != nil {
				return api.Errorf(api.ExitError, "%v (the last list stays)", err)
			}
			return nil
		}}
}
