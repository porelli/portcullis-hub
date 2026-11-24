package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// mailProviderID is the fixtures' mail provider instance (the shared
// vectors' template id); otherMailID a second mail template's.
const (
	mailProviderID = "mailsrv"
	otherMailID    = "othermail"
)

// mailTemplateFiles is the stalwart-shaped template of the shared mail
// vectors (internal/templates/testdata/mail_vectors.json) as files.
func mailTemplateFiles(t *testing.T) map[string]string {
	t.Helper()
	return mailVectorFiles(t, "stalwart-shaped ok")
}

// mailVectorFiles is one ok vector of the shared mail vectors as files.
func mailVectorFiles(t *testing.T, name string) map[string]string {
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
		if v.Name == name {
			return map[string]string{"manifest.yaml": v.Manifest, "compose.yml": v.Compose, "gate.sh": "#!/bin/sh\n", "unbound.conf": "server:\n"}
		}
	}
	t.Fatalf("no vector %q", name)
	return nil
}

// newMailSlotFixture is a fixture whose source has the mail template
// mailsrv; wired: it is the wired provider (normal mode).
func newMailSlotFixture(t *testing.T, wired bool, others ...string) *fixture {
	t.Helper()
	return newMailSlotFixtureFrom(t, mailTemplateFiles(t), wired, others...)
}

// newMailSlotFixtureFrom is newMailSlotFixture with mailsrv's files.
func newMailSlotFixtureFrom(t *testing.T, files map[string]string, wired bool, others ...string) *fixture {
	t.Helper()
	return newMailSlotFixtureApps(t, files, wired, nil, others...)
}

// newMailSlotFixtureApps is newMailSlotFixtureFrom with more (app)
// templates in the source: id → files.
func newMailSlotFixtureApps(t *testing.T, files map[string]string, wired bool, apps map[string]map[string]string, others ...string) *fixture {
	t.Helper()
	extra := map[string]map[string]string{mailProviderID: files}
	for id, fs := range apps {
		extra[id] = fs
	}
	for _, id := range others {
		fs := mailTemplateFiles(t)
		fs["compose.yml"] = strings.ReplaceAll(fs["compose.yml"], "templates/"+mailProviderID+"/", "templates/"+id+"/")
		extra[id] = fs
	}
	f := newFixtureExtra(t, extra, func(root string, c *Config) {
		c.SecretsDir = filepath.Join(root, "secrets")
		if err := os.Mkdir(c.SecretsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		c.MailSlotDir = filepath.Join(root, "mail-slot")
		if err := os.Mkdir(c.MailSlotDir, 0o750); err != nil {
			t.Fatal(err)
		}
		c.MailGID = os.Getgid()
		c.MailProviderSlotDir = filepath.Join(root, "mail-provider-slot")
		if err := os.Mkdir(c.MailProviderSlotDir, 0o750); err != nil {
			t.Fatal(err)
		}
	})
	if f.h.Template(mailProviderID) == nil {
		t.Fatal("the mail template didn't load (see the log)")
	}
	if wired {
		tp := f.h.Template(mailProviderID)
		hash, err := templates.MailBlockHash(tp.Path, tp.Manifest.Mail, tp.ReadCompose())
		if err != nil {
			t.Fatal(err)
		}
		f.h.mu.Lock()
		f.h.st.Mail.Provider = &state.MailProvider{Instance: mailProviderID, Template: mailProviderID, Source: "local", BlockHash: hash}
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
