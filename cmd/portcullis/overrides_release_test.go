//go:build !sshtest

package main

import (
	"strings"
	"testing"
)

// The release binary has no --people-url and refuses an agent.json
// that sets people_url (fail closed; ruling: test builds only).
func TestReleaseHasNoPeopleURL(t *testing.T) {
	c := enrollCmd()
	if c.Flags().Lookup("people-url") != nil {
		t.Fatal("--people-url in a release build")
	}
	c.SetArgs([]string{"--people-url", "https://people.example.com"})
	c.SilenceUsage, c.SilenceErrors = true, true
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("--people-url accepted: %v", err)
	}
	if _, err := hostClient("example.com", "https://evil.example.net", ""); err == nil || !strings.Contains(err.Error(), "people_url") {
		t.Errorf("people_url accepted: %v", err)
	}
	if _, err := hostClient("example.com", "", ""); err != nil {
		t.Errorf("default: %v", err)
	}
}
