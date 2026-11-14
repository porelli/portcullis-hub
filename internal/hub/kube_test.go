package hub

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

const lanManifest = `name: Lan
description: x
version: "1.0"
category: x
ai: {unsupported: "test fixture"}
auth:
  method: custom
ports:
  - key: SMB_PORT
    label: SMB
    container: 445
    default: 445
    lan_only: true
  - key: WEB_PORT
    label: Web
    container: 80
    default: 8085
`

const lanCompose = "services:\n  smb:\n    image: x\n    user: \"10001\"\n    ports:\n      - \"${SMB_PORT:-445}:445\"\n      - \"${WEB_PORT:-8085}:80\"\n    volumes:\n      - ./templates/lan/conf:/conf:ro\n"

// TestKubeUpProjectInputs: under Kubernetes an up's project carries the
// loaded model and the inputs read from the Hub's disk and state; under
// Docker nothing is loaded.
func TestKubeUpProjectInputs(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"lan": {lanManifest, lanCompose}})
	tp := f.h.Template("lan")
	if tp == nil {
		t.Fatal("lan fixture not loaded")
	}
	p, err := f.h.upProject(context.Background(), tp)
	if err != nil || p.Model != nil || p.Inputs != nil {
		t.Fatalf("docker: %+v %v", p, err)
	}
	f.h.cfg.Runtime = runtime.KindKubernetes
	dir := filepath.Join(f.project, "templates", "lan", "conf")
	os.MkdirAll(dir, 0o755)
	writeFile(t, filepath.Join(dir, "a.conf"), "x=1\n")
	p, err = f.h.upProject(context.Background(), tp)
	if err != nil {
		t.Fatal(err)
	}
	if p.Model == nil || p.Model.Services["smb"].Image != "x" {
		t.Fatalf("model %+v", p.Model)
	}
	in := p.Inputs
	if in == nil || in.Template != "lan" || string(in.TemplateFiles["conf/a.conf"]) != "x=1\n" {
		t.Fatalf("inputs %+v", in)
	}
	if !in.LanOnly[445] || in.LanOnly[8085] {
		t.Errorf("lan only %v", in.LanOnly)
	}
}
