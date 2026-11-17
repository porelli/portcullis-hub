package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
)

// mailProviderID is the fixtures' mail provider instance (the shared
// vectors' template id).
const mailProviderID = "mailsrv"

// mailTemplateFiles is the stalwart-shaped template of the shared mail
// vectors (internal/templates/testdata/mail_vectors.json) as files.
func mailTemplateFiles(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "templates", "testdata", "mail_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name, Manifest, Compose string
	}
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.Name == "stalwart-shaped ok" {
			return map[string]string{"manifest.yaml": v.Manifest, "compose.yml": v.Compose, "gate.sh": "#!/bin/sh\n", "unbound.conf": "server:\n"}
		}
	}
	t.Fatal("no stalwart-shaped vector")
	return nil
}

// newMailSlotFixture is a fixture whose source has the mail template
// mailsrv; wired: it is the wired provider (normal mode).
func newMailSlotFixture(t *testing.T, wired bool) *fixture {
	t.Helper()
	f := newFixtureExtra(t, map[string]map[string]string{mailProviderID: mailTemplateFiles(t)})
	if f.h.Template(mailProviderID) == nil {
		t.Fatal("the mail template didn't load (see the log)")
	}
	if wired {
		f.h.mu.Lock()
		f.h.st.Mail.Provider = &state.MailProvider{Instance: mailProviderID, Template: mailProviderID, Source: "local"}
		f.h.mu.Unlock()
	}
	return f
}

// providerContainer is the wired provider's sessions.restart container
// as compose labels it.
func providerContainer(id string) docker.Container {
	return docker.Container{ID: id, Labels: map[string]string{docker.LabelProject: "portcullis-" + mailProviderID, docker.LabelService: "stalwart",
		"com.docker.compose.oneoff": "False"}}
}
