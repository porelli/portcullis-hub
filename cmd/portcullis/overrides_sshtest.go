//go:build sshtest

package main

import "github.com/spf13/cobra"

// testOverrides: a -tags sshtest build (the container tests only) has
// the hidden --people-url (the fake Hub; TLS still verified, the
// first CA still pinned by the code). Never in a release binary.
const testOverrides = true

func addTestOverrideFlags(c *cobra.Command, peopleURL *string) {
	f := c.Flags()
	f.StringVar(peopleURL, "people-url", "", "")
	_ = f.MarkHidden("people-url")
}
