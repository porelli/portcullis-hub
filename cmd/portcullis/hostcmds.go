package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/host"
	"github.com/portcullis/hub/internal/cliapi"
)

// addHostCommands adds the managed host's commands.
func addHostCommands(h *cobra.Command) {
	h.AddCommand(enrollCmd(), syncCmd(), hostStatusCmd(), hostRemoveCmd(), certifyCmd())
}

// readCode reads the enrolment code: stdin when no argument, a hidden
// prompt for "-"; never from argv (it's a secret).
func readCode(args []string, stdin io.Reader) (string, error) {
	if len(args) == 1 && args[0] != "-" {
		return "", api.Errorf(api.ExitUsage, "the enrolment code is a secret: never on the command line. Use: sudo portcullis host enroll < code.txt (or - to type it)")
	}
	if len(args) == 1 {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return "", api.Errorf(api.ExitUsage, "- needs a terminal: or pipe the code on stdin")
		}
		fmt.Fprint(os.Stderr, "Enrolment code (not shown): ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	b, err := io.ReadAll(io.LimitReader(stdin, 8<<10))
	return strings.TrimSpace(string(b)), err
}

func hostClient(domain, peopleURL, caFile string) (*api.Client, error) {
	base := "https://people." + domain
	if peopleURL != "" {
		if !testOverrides {
			return nil, api.Errorf(api.ExitUsage, "%s sets people_url, which this binary doesn't accept (test builds only): re-enrol this host", host.AgentFile)
		}
		base = peopleURL
	}
	return api.New(base, version, caFile)
}

func enrollCmd() *cobra.Command {
	var service, uidRange, caFile, peopleURL string
	var noBG bool
	ceil := cliapi.DefaultCeiling()
	c := &cobra.Command{Use: "enroll [-]", Short: "Managed host: enrol with the one-time code (read from stdin; - prompts)", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := needRoot(); err != nil {
				return err
			}
			raw, err := readCode(args, os.Stdin)
			if err != nil {
				return err
			}
			code, err := cliapi.ParseEnrolCode(raw)
			if err != nil {
				return api.Errorf(api.ExitUsage, "%v", err)
			}
			if service != "auto" && service != "none" {
				return api.Errorf(api.ExitUsage, "--service is auto or none")
			}
			lo, hi, ok := strings.Cut(uidRange, "-")
			a, e1 := strconv.Atoi(lo)
			b, e2 := strconv.Atoi(hi)
			if !ok || e1 != nil || e2 != nil {
				return api.Errorf(api.ExitUsage, "--uid-range is <first>-<last>")
			}
			ceil.UIDRange = [2]int{a, b}
			if noBG {
				ceil.BreakglassAccount = ""
			}
			ceil.ProtectedAccounts = nil
			if ceil.BreakglassAccount != "" {
				ceil.ProtectedAccounts = []string{ceil.BreakglassAccount}
			}
			if err := confirmCeiling(ceil); err != nil {
				return err
			}
			cl, err := hostClient(code.Domain, peopleURL, caFile)
			if err != nil {
				return err
			}
			self, _ := os.Executable()
			if err := host.Enroll(cmd.Context(), host.OS{}, host.EnrollOptions{Code: code, Ceiling: ceil, NoBreakglass: noBG, Service: service, Self: self, CAFile: caFile, PeopleURL: peopleURL, Client: cl}); err != nil {
				return api.Errorf(api.ExitCode(err), "%v", err)
			}
			fmt.Println("Enrolled as " + code.HostID + " in " + code.Domain + ".")
			if service == "none" {
				fmt.Println("Now run portcullis host sync (in the foreground, or under your init system).")
			}
			return nil
		}}
	f := c.Flags()
	f.StringVar(&service, "service", "auto", "auto (systemd, then launchd) or none (run portcullis host sync yourself)")
	f.BoolVar(&ceil.AllowSudo, "allow-sudo", true, "the Hub may give accounts sudo")
	f.BoolVar(&ceil.AllowRootLogin, "allow-root-login", false, "the Hub may grant logins as root")
	f.StringVar(&ceil.BreakglassAccount, "breakglass-account", cliapi.DefaultBreakglassAccount, "the account with its own authorized_keys Portcullis never touches")
	f.BoolVar(&noBG, "no-breakglass-i-have-console-access", false, "no break-glass account: you have console access")
	f.IntVar(&ceil.MaxAccounts, "max-accounts", cliapi.DefaultMaxAccounts, "at most this many Portcullis accounts")
	f.StringVar(&uidRange, "uid-range", "20000-59999", "the uids Portcullis accounts may use")
	f.StringVar(&caFile, "ca-file", "", "trust an extra CA (a test server's staging root)")
	addTestOverrideFlags(c, &peopleURL)
	return c
}

// confirmCeiling shows the ceiling; on a terminal it asks (C39).
func confirmCeiling(c cliapi.Ceiling) error {
	fmt.Fprintf(os.Stderr, "This host's ceiling (Portcullis can never exceed it):\n  sudo allowed: %v\n  root logins allowed: %v\n  uids: %d-%d\n  break-glass account: %q\n  protected: every account below uid 1000, %v\n  at most %d accounts\n",
		c.AllowSudo, c.AllowRootLogin, c.UIDRange[0], c.UIDRange[1], c.BreakglassAccount, c.ProtectedAccounts, c.MaxAccounts)
	if !term.IsTerminal(int(os.Stderr.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	fmt.Fprint(os.Stderr, "Use this ceiling? [Y/n] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.EqualFold(strings.TrimSpace(line), "n") {
		return api.Errorf(api.ExitUsage, "change it with the flags (see portcullis host enroll --help)")
	}
	return nil
}

func syncCmd() *cobra.Command {
	var once bool
	c := &cobra.Command{Use: "sync", Short: "Managed host: keep this host current (the portcullis-host-sync service)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := needRoot(); err != nil {
				return err
			}
			cfg, err := host.LoadAgentConfig(host.OS{})
			if err != nil {
				return err
			}
			cl, err := hostClient(cfg.Domain, cfg.PeopleURL, cfg.CAFile)
			if err != nil {
				return err
			}
			return host.Sync(cmd.Context(), host.OS{}, host.SyncOptions{Client: cl, Once: once})
		}}
	c.Flags().BoolVar(&once, "once", false, "one round, then exit")
	return c
}

func hostStatusCmd() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Managed host: the bundle's age, serial and findings", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sys := host.OS{}
			cfg, err := host.LoadAgentConfig(sys)
			if err != nil {
				return err
			}
			st, err := host.LoadState(sys)
			if err != nil || st == nil {
				return errors.New("no bundle applied yet")
			}
			fmt.Printf("host %s of %s\nserial %d, applied %s ago, reported %s ago\n", cfg.HostID, cfg.Domain, st.Serial,
				time.Since(st.Applied).Round(time.Second), time.Since(st.Reported).Round(time.Second))
			if len(st.Locked) > 0 {
				fmt.Printf("locked accounts: %s\n", strings.Join(st.Locked, ", "))
			}
			return nil
		}}
}

func hostRemoveCmd() *cobra.Command {
	var del bool
	c := &cobra.Command{Use: "remove", Short: "Remove every Portcullis file from this host (locks or deletes its accounts)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := needRoot(); err != nil {
				return err
			}
			none := false
			if cfg, err := host.LoadAgentConfig(host.OS{}); err == nil {
				none = cfg.ServiceNone
			}
			if err := host.RemoveTrust(cmd.Context(), host.OS{}, del, none, false); err != nil {
				return api.Errorf(api.ExitError, "%v", err)
			}
			fmt.Println("Removed. The host's own login paths are as they were.")
			return nil
		}}
	c.Flags().BoolVar(&del, "delete-accounts", false, "delete the Portcullis accounts (homes kept under /home/.portcullis-removed)")
	return c
}

func certifyCmd() *cobra.Command {
	var o host.CertifyOptions
	c := &cobra.Command{Use: "certify", Short: "Sign an unmanaged host's key (administrators, a security key sign-in)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := pickDomain(nil, o.Login.Domain)
			if err != nil {
				return err
			}
			o.Login.Domain, o.Login.Version, o.Login.OpenBrowser = d, version, browser.OpenURL
			return host.Certify(cmd.Context(), o)
		}}
	f := c.Flags()
	f.StringVar(&o.Login.Domain, "domain", "", "the Portcullis domain")
	f.StringVar(&o.HostGroup, "host-group", "", "the host group whose patterns the names match")
	f.StringVar(&o.KeyFile, "key", "/etc/ssh/ssh_host_ed25519_key.pub", "the host's public key")
	f.StringSliceVar(&o.Names, "name", nil, "a name or address the certificate vouches for (repeatable)")
	f.StringVar(&o.Login.Method, "method", "security_key", "security_key or yubikey_cert")
	f.BoolVar(&o.Login.NoBrowser, "no-browser", false, "print the sign-in address instead of opening a browser")
	f.StringVar(&o.Login.CAFile, "ca-file", "", "trust an extra CA (PEM)")
	return c
}
