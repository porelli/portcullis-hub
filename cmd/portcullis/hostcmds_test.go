package main

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
)

func TestEnrolCodeFromStdinNeverArgv(t *testing.T) {
	if _, err := readCode([]string{"pcenrol1.eyJkIjoieCJ9"}, strings.NewReader("")); api.ExitCode(err) != api.ExitUsage || !strings.Contains(err.Error(), "never on the command line") {
		t.Errorf("argv code: %v", err)
	}
	got, err := readCode(nil, strings.NewReader("  pcenrol1.abc\n"))
	if err != nil || got != "pcenrol1.abc" {
		t.Errorf("stdin: %q %v", got, err)
	}
	// "-" needs a terminal (tests have none).
	if _, err := readCode([]string{"-"}, strings.NewReader("")); err == nil {
		t.Error("- without a terminal")
	}
}
