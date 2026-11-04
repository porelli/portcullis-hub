package templates

import (
	"strings"
	"testing"
)

// Plan 3 Task 10: the reserved variables a file-sharing template reads
// (F35 / F36, contract §3.1 and §13.15 Variables) and render.expand_members
// (§13.5).

// slotOpt is a share slot's folder option on service smb.
const slotOpt = `{key: share1_folder, label: Share 1 folder, type: path, target: {service: smb, mount: /shares/1}, ` +
	`folder: {access: write, runs_as: {uid_from: uid}, joins_group: template}}`

// envCompose is a compose file whose service svc has environment KEY: val.
func envCompose(svc, val string) string {
	out := "services:\n  smb:\n    image: x\n  other:\n    image: x\n"
	return strings.Replace(out, "  "+svc+":\n    image: x\n", "  "+svc+":\n    image: x\n    environment:\n      KEY: "+val+"\n", 1)
}

func TestLocalNetworksVarForms(t *testing.T) {
	m := smb(ps())
	runSettingsCases(t, []settingsCase{
		{"exact", m, envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS}"), "", ""},
		{"exact in text", m, envCompose("smb", "'allow ${PORTCULLIS_LOCAL_NETWORKS} end'"), "", ""},
		{"list form", m, "services:\n  smb:\n    image: x\n    environment:\n      - NETS=${PORTCULLIS_LOCAL_NETWORKS}\n  other:\n    image: x\n", "", ""},
		{"in a command", m, "services:\n  smb:\n    image: x\n    command: [run, '${PORTCULLIS_LOCAL_NETWORKS}']\n  other:\n    image: x\n", "", ""},
		{"default", m, envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS:-0.0.0.0/0}"), "", "only as exactly ${PORTCULLIS_LOCAL_NETWORKS}"},
		{"dash default", m, envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS-0.0.0.0/0}"), "", "only as exactly ${PORTCULLIS_LOCAL_NETWORKS}"},
		{"alternate", m, envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS:+x}"), "", "only as exactly"},
		{"plus", m, envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS+x}"), "", "only as exactly"},
		{"error form", m, envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS?unset}"), "", "only as exactly"},
		{"colon error form", m, envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS:?unset}"), "", "only as exactly"},
		{"bare", m, envCompose("smb", "$PORTCULLIS_LOCAL_NETWORKS"), "", "only as exactly"},
		{"escaped is text", m, envCompose("smb", "$${PORTCULLIS_LOCAL_NETWORKS:-x}"), "", ""},
	})
	for _, manifest := range []string{
		smbHead + "env:\n  - {key: PORTCULLIS_LOCAL_NETWORKS}\n" + opts(connectOpt, uidOpt, ps()),
	} {
		if _, err := build("app", "src", "", []byte(manifest), []byte(smbCompose), "example.org", nil); err == nil || !strings.Contains(err.Error(), "PORTCULLIS_LOCAL_NETWORKS") {
			t.Errorf("a manifest declaring PORTCULLIS_LOCAL_NETWORKS: %v", err)
		}
	}
	if !ReservedVar(VarLocalNetworks) || VarLocalNetworks != "PORTCULLIS_LOCAL_NETWORKS" {
		t.Error("PORTCULLIS_LOCAL_NETWORKS is not a reserved instance variable")
	}
}

func TestUsesLocalNetworks(t *testing.T) {
	for _, c := range []struct {
		compose string
		want    bool
	}{
		{envCompose("smb", "${PORTCULLIS_LOCAL_NETWORKS}"), true},
		{smbCompose, false},
		{envCompose("smb", "$${PORTCULLIS_LOCAL_NETWORKS}"), false},
		{"# ${PORTCULLIS_LOCAL_NETWORKS}\n" + smbCompose, false},
	} {
		tm, err := build("app", "src", "", []byte(smb(ps())), []byte(c.compose), "example.org", nil)
		if err != nil {
			t.Fatalf("%q: %v", c.compose, err)
		}
		if tm.UsesLocalNetworks != c.want {
			t.Errorf("%q: UsesLocalNetworks = %v, want %v", c.compose, tm.UsesLocalNetworks, c.want)
		}
		if v, err := tm.Instance("app-2", nil, "example.org"); err != nil || v.UsesLocalNetworks != c.want {
			t.Errorf("%q: an instance view lost UsesLocalNetworks (%v)", c.compose, err)
		}
	}
}

func TestFolderGIDVarForms(t *testing.T) {
	m := smb(ps(), slotOpt)
	plainPath := `{key: data, label: Data, type: path, target: {service: smb, mount: /data}}`
	runSettingsCases(t, []settingsCase{
		{"on the folder's service", m, envCompose("smb", "${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}"), "", ""},
		{"list form", m, "services:\n  smb:\n    image: x\n    environment:\n      - SHARE1_GID=${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}\n  other:\n    image: x\n", "", ""},
		{"another service", m, envCompose("other", "${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}"), "", "PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"},
		{"default", m, envCompose("smb", "${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER:-60001}"), "", "PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"},
		{"bare", m, envCompose("smb", "$PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"), "", "PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"},
		{"inside text", m, envCompose("smb", "'g${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}'"), "", "PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"},
		{"uid var", m, envCompose("smb", "${PORTCULLIS_FOLDER_UID_SHARE1_FOLDER}"), "", "PORTCULLIS_FOLDER_UID_SHARE1_FOLDER"},
		{"unknown key", m, envCompose("smb", "${PORTCULLIS_FOLDER_GID_NOPE}"), "", "PORTCULLIS_FOLDER_GID_NOPE"},
		{"no folder block", smb(ps(), plainPath), envCompose("smb", "${PORTCULLIS_FOLDER_GID_DATA}"), "", "PORTCULLIS_FOLDER_GID_DATA"},
		{"in a command", m, "services:\n  smb:\n    image: x\n    command: ['${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}']\n  other:\n    image: x\n", "", "PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"},
		{"in a label too", m, "services:\n  smb:\n    image: x\n    environment:\n      G: ${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}\n    labels:\n      x: ${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}\n  other:\n    image: x\n", "", "PORTCULLIS_FOLDER_GID_SHARE1_FOLDER"},
		{"another folder prefix", m, envCompose("smb", "${PORTCULLIS_FOLDER_X}"), "", "PORTCULLIS_FOLDER_X"},
	})
	// No settings at all: still refused.
	if _, err := build("app", "src", "", []byte("name: X\nauth: {method: custom}\n"), []byte(envCompose("smb", "${PORTCULLIS_FOLDER_GID_X}")), "example.org", nil); err == nil || !strings.Contains(err.Error(), "PORTCULLIS_FOLDER_GID_X") {
		t.Errorf("a settings-less template referencing a folder variable: %v", err)
	}
}

func TestExpandMembersRule(t *testing.T) {
	readers := func(d string) string {
		return `{key: share1_readers, label: Readers, type: groups, delivery: [` + d + `]}`
	}
	runSettingsCases(t, []settingsCase{
		{"file", smb(ps(), readers(`{file: {name: people, render: {expand_members: true}}}`)), smbCompose, "", ""},
		{"group", smb(ps(), `{key: g, label: G, type: group, delivery: [{file: {name: people, render: {expand_members: true}}}]}`), smbCompose, "", ""},
		{"env", smb(ps(), `{key: share1_readers, label: Readers, type: groups, delivery: [{env: R, render: {expand_members: true}}]}`), envCompose("smb", "${R}"), "share1_readers", "expand_members is for file deliveries"},
		{"hook", smb(ps(), readers(`{hook: sync, render: {expand_members: true}}`)), smbCompose, "share1_readers", "expand_members is for file deliveries"},
		{"string", smb(ps(), `{key: s, label: S, type: string, delivery: [{file: {name: people, render: {expand_members: true}}}]}`), smbCompose, "s", "expand_members is for group and groups options"},
	})
}
