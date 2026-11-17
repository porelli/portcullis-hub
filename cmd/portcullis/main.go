// Command portcullis is the Portcullis CLI (contract §18): `portcullis
// login` for people and `portcullis host …` for hosts. It imports nothing
// from the Hub but internal/cliapi (deps_test.go). No telemetry, no
// update check: it talks only to its own Portcullis and its loopback.
package main

import (
	"bufio"
	"context"

	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/cmd/portcullis/internal/config"
	"github.com/portcullis/hub/cmd/portcullis/internal/login"
	"github.com/portcullis/hub/cmd/portcullis/internal/sshconf"
	"github.com/portcullis/hub/internal/cliapi"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	root := rootCmd()
	err := root.ExecuteContext(ctx)
	if err != nil && err.Error() != "" {
		fmt.Fprintln(os.Stderr, "portcullis: "+err.Error())
	}
	os.Exit(api.ExitCode(err))
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{Use: "portcullis", Short: "Sign in to Portcullis and get SSH certificates", SilenceUsage: true, SilenceErrors: true}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return api.Errorf(api.ExitUsage, "%v", err) })
	var debug bool
	root.PersistentFlags().BoolVar(&debug, "debug", false, "print request lines (codes, keys and tokens redacted)")
	common := func(o *login.Options) {
		o.Version = version
		o.OpenBrowser = browser.OpenURL
		if debug {
			o.Debug = os.Stderr
		}
	}
	// login
	var lo login.Options
	var domainFlag string
	loginCmd := &cobra.Command{Use: "login [<domain>]", Short: "Sign in in your browser and load SSH certificates into your agent", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := pickDomain(args, domainFlag)
			if err != nil {
				return err
			}
			o := lo
			o.Domain = d
			common(&o)
			_, err = login.Run(cmd.Context(), o)
			return err
		}}
	loginCmd.Flags().StringVar(&domainFlag, "domain", "", "the Portcullis domain (with several configured)")
	loginCmd.Flags().StringVar(&lo.Method, "method", "", "ask for one sign-in method, e.g. security_key")
	loginCmd.Flags().StringVar(&lo.KeyFile, "key", "", "sign your own key (its .pub; it must be in your ssh-agent), e.g. a FIDO key")
	loginCmd.Flags().BoolVar(&lo.WriteFiles, "write-files", false, "also write this login's private key to ~/.ssh/portcullis (without an ssh-agent)")
	loginCmd.Flags().BoolVar(&lo.NoBrowser, "no-browser", false, "print the sign-in address instead of opening a browser")
	loginCmd.Flags().StringVar(&lo.CAFile, "ca-file", "", "trust an extra CA (PEM), e.g. a test server's staging root (or PORTCULLIS_CA_FILE)")
	root.AddCommand(loginCmd)

	// status
	root.AddCommand(&cobra.Command{Use: "status", Short: "The Portcullis certificates in your agent and files (no network)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := login.Options{}
			common(&o)
			return login.Status(o)
		}})

	// logout
	var revoke bool
	var logoutDomain string
	logoutCmd := &cobra.Command{Use: "logout", Short: "Remove the Portcullis keys from your agent and delete the written files", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := pickDomain(nil, logoutDomain)
			if err != nil {
				return err
			}
			o := login.Options{Domain: d}
			common(&o)
			return login.Logout(cmd.Context(), o, revoke)
		}}
	logoutCmd.Flags().BoolVar(&revoke, "revoke", false, "also revoke this login's certificates (signs you in again)")
	logoutCmd.Flags().StringVar(&logoutDomain, "domain", "", "the Portcullis domain")
	root.AddCommand(logoutCmd)

	// ssh-config
	var install bool
	sshCfg := &cobra.Command{Use: "ssh-config", Short: "Print, or add after asking, the Include line for ~/.ssh/config", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !install {
				fmt.Println(cliapi.IncludeLine)
				return nil
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			done, err := sshconf.Install(home, confirm("Add \""+cliapi.IncludeLine+"\" at the top of ~/.ssh/config?"))
			if err == nil && done {
				fmt.Println("Added.")
			} else if err == nil && sshconf.Installed(home) {
				fmt.Println("Already there.")
			}
			return err
		}}
	sshCfg.Flags().BoolVar(&install, "install", false, "add the line to ~/.ssh/config (asks first)")
	root.AddCommand(sshCfg)

	// open
	var openDomain string
	openCmd := &cobra.Command{Use: "open [<name>]", Short: "Open an app (https://<name>.<domain>/) or the portal in your browser", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := pickDomain(nil, openDomain)
			if err != nil {
				return err
			}
			u := "https://" + d + "/"
			if len(args) == 1 {
				if !cliapi.ValidHostGroupID(args[0]) {
					return api.Errorf(api.ExitUsage, "%q isn't an app name", api.Printable(args[0]))
				}
				u = "https://" + args[0] + "." + d + "/"
			}
			return browser.OpenURL(u)
		}}
	openCmd.Flags().StringVar(&openDomain, "domain", "", "the Portcullis domain")
	root.AddCommand(openCmd)

	// version
	root.AddCommand(&cobra.Command{Use: "version", Short: "The CLI's version and API version (no network)", Args: cobra.NoArgs,
		Run: func(*cobra.Command, []string) { fmt.Printf("portcullis %s (api %d)\n", version, cliapi.APIVersion) }})

	root.AddCommand(hostCmd())
	return root
}

// pickDomain: the argument, --domain, or the configured one.
func pickDomain(args []string, flag string) (string, error) {
	if len(args) == 1 {
		return strings.ToLower(args[0]), nil
	}
	if flag != "" {
		return strings.ToLower(flag), nil
	}
	f, err := config.Load("")
	if err != nil {
		return "", err
	}
	d, err := f.Pick("")
	if err != nil {
		return "", api.Errorf(api.ExitUsage, "%v", err)
	}
	return d, nil
}

// confirm asks a y/N question on the terminal (never yes without one).
func confirm(q string) func() bool {
	return func() bool {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, "Not a terminal: nothing changed. Add this line yourself: "+cliapi.IncludeLine)
			return false
		}
		fmt.Fprint(os.Stderr, q+" [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
	}
}
