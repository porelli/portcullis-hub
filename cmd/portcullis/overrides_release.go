//go:build !sshtest

package main

import "github.com/spf13/cobra"

// testOverrides: the release binary takes no test overrides (ruling:
// a flag pointing the CLI at another server is a social-engineering
// lever). Only a -tags sshtest build has them.
const testOverrides = false

func addTestOverrideFlags(*cobra.Command, *string) {}
