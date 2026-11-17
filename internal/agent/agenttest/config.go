// Package agenttest has test stand-ins for the worker agent.
package agenttest

import (
	"context"
	"os"

	"github.com/compose-spec/compose-go/v2/cli"

	"github.com/portcullis/hub/internal/compose"
)

// Config stands in for `docker compose config --format json` in tests
// (no compose CLI there): compose-go loads the files as the CLI does —
// the env file only, every profile, paths resolved against the project
// directory — and marshals the result.
func Config(ctx context.Context, p compose.Project) ([]byte, error) {
	opts := []cli.ProjectOptionsFn{cli.WithName(p.Name), cli.WithWorkingDirectory(p.ProjectDir), cli.WithEnv([]string{}),
		cli.WithProfiles([]string{"*"}), cli.WithResolvedPaths(true)}
	if p.EnvFile != "" {
		if _, err := os.Stat(p.EnvFile); err == nil {
			opts = append(opts, cli.WithEnvFiles(p.EnvFile), cli.WithDotEnv)
		}
	}
	po, err := cli.NewProjectOptions(p.Files, opts...)
	if err != nil {
		return nil, err
	}
	m, err := po.LoadProject(ctx)
	if err != nil {
		return nil, err
	}
	return m.MarshalJSON()
}
