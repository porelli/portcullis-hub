package main

import (
	"github.com/spf13/cobra"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
)

// hostCmd is `portcullis host …` (Tasks 12–14).
func hostCmd() *cobra.Command {
	return &cobra.Command{Use: "host", Short: "Set up and keep a host trusting Portcullis certificates (needs root)",
		RunE: func(*cobra.Command, []string) error {
			return api.Errorf(api.ExitUsage, "portcullis host: enroll, trust, sync, status, remove or certify")
		}}
}
