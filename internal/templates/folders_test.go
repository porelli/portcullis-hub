package templates

import (
	"strings"
	"testing"
)

// Shared folders (contract §13.15): the folder block, checks, lan_only
// ports. Every refusal names the option and the specific reason.

// fCompose has PUID/PGID images and services with each compose user: form.
const fCompose = "services:\n  web:\n    image: x\n    environment:\n      PUID: ${PUID:-1000}\n      PGID: ${PGID:-1000}\n    labels:\n" +
	"      traefik.http.routers.app.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`)\n" +
	"      traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"  fixed:\n    image: x\n    user: \"1000:1000\"\n" +
	"  envuser:\n    image: x\n    user: \"${PUID:-1000}:${PGID:-1000}\"\n" +
	"  named:\n    image: x\n    user: www-data\n"

const (
	puidOpt = "{key: puid, label: P, type: int, default: 1000}"
	pgidOpt = "{key: pgid, label: G, type: int, default: 1000}"
)

// fpath is a path option on service svc with the given extra fields.
func fpath(key, svc, extra string) string {
	return "{key: " + key + ", label: X, type: path, target: {service: " + svc + ", mount: /" + key + "}" + extra + "}"
}

func folderCases(t *testing.T, cases []settingsCase) {
	t.Helper()
	for i := range cases {
		if cases[i].compose == "" {
			cases[i].compose = fCompose
		}
	}
	runSettingsCases(t, cases)
}

const rw = ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}"

func TestFolderOnlyOnInstancePath(t *testing.T) {
	folderCases(t, []settingsCase{
		{"string", hdrHead + opts("{key: theme, label: X, type: string, folder: {access: read, runs_as: {uid: 1, gid: 1}}}"), hdrCompose, "theme", "folder is for path options"},
		{"person path", hdrHead + opts("{key: media, label: X, type: path, scope: person, default: /srv/x, resolve: priority, target: {service: web, mount: /m}, folder: {access: read, runs_as: {uid: 1, gid: 1}}}"), "", "media", "folder is for path options with scope instance"},
		{"ok", hdrHead + opts(fpath("media", "web", rw)), "", "", ""},
	})
}

func TestFolderAccessAndRunsAsRequired(t *testing.T) {
	folderCases(t, []settingsCase{
		{"no access", hdrHead + opts(fpath("media", "web", ", folder: {runs_as: {uid: 1000, gid: 1000}}")), "", "media", "folder.access"},
		{"rw", hdrHead + opts(fpath("media", "web", ", folder: {access: rw, runs_as: {uid: 1000, gid: 1000}}")), "", "media", `folder.access "rw" must be read or write`},
		{"no runs_as", hdrHead + opts(fpath("media", "web", ", folder: {access: read}")), "", "media", "folder.runs_as is required"},
		{"ok", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")), "", "", ""},
		{"negative", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: -1, gid: 1000}}")), "", "media", "folder.runs_as.uid"},
	})
}

func TestRunsAsOneSourcePerID(t *testing.T) {
	folderCases(t, []settingsCase{
		{"two uid sources", hdrHead + opts(puidOpt, fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1, uid_env: PUID, gid: 1}}")), "", "media", "folder.runs_as.uid: exactly one of uid, uid_env"},
		{"no uid source", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {gid: 1}}")), "", "media", "folder.runs_as.uid: exactly one of uid, uid_env"},
		{"no gid source", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1}}")), "", "media", "folder.runs_as.gid: exactly one of gid, gid_env"},
	})
}

func TestRunsAsEnvNamesOption(t *testing.T) {
	folderCases(t, []settingsCase{
		{"no option", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), "", "media", "folder.runs_as.uid_env PUID is not the env name of an instance int option"},
		{"reserved", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PORTCULLIS_X, gid: 1}}")), "", "media", "folder.runs_as.uid_env PORTCULLIS_X is reserved"},
		{"string option", hdrHead + opts("{key: puid, label: P, type: string, default: '1000'}", fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), "", "media", "not the env name of an instance int option"},
		{"ok", hdrHead + opts(puidOpt, pgidOpt, fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), "", "", ""},
		{"env delivery name", hdrHead + opts("{key: user_id, label: P, type: int, default: 1000, delivery: [{env: PUID}]}", fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid: 1}}")), "", "", ""},
	})
}

func TestRunsAsMatchesComposeUser(t *testing.T) {
	folderCases(t, []settingsCase{
		{"gid differs", hdrHead + opts(fpath("media", "fixed", ", folder: {access: read, runs_as: {uid: 1000, gid: 100}}")), "", "media", `folder.runs_as.gid 100 doesn't match service fixed's compose user: "1000:1000"`},
		{"uid differs", hdrHead + opts(fpath("media", "fixed", ", folder: {access: read, runs_as: {uid: 0, gid: 1000}}")), "", "media", `folder.runs_as.uid 0 doesn't match`},
		{"numbers match", hdrHead + opts(fpath("media", "fixed", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")), "", "", ""},
		{"env form", hdrHead + opts(puidOpt, pgidOpt, fpath("media", "envuser", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), "", "", ""},
		{"env user, numbers", hdrHead + opts(puidOpt, pgidOpt, fpath("media", "envuser", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")), "", "media", "folder.runs_as.uid: service envuser's compose user: takes it from ${PUID}: use uid_env: PUID"},
		{"numeric user, env", hdrHead + opts(puidOpt, pgidOpt, fpath("media", "fixed", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), "", "media", "folder.runs_as.uid_env PUID doesn't match service fixed's compose user"},
		{"named user", hdrHead + opts(fpath("media", "named", ", folder: {access: read, runs_as: {uid: 33, gid: 33}}")), "", "media", "give numbers in compose `user:`"},
		{"named user, no folder", hdrHead + opts(fpath("media", "named", "")), "", "", ""},
	})
}

func TestFolderGIDRangeRefused(t *testing.T) {
	folderCases(t, []settingsCase{
		{"runs_as.gid", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 60000}}")), "", "media", "gid 60000 is in 60000-60999 (shared folder groups)"},
		{"writes_as.gid", hdrHead + opts(fpath("media", "web", ", writes_as: {uid: 1000, gid: 60999}")), "", "media", "gid 60999 is in 60000-60999"},
		{"edge ok", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 60000, gid: 61000}}")), "", "", ""},
		{"compose user gid", hdrHead + opts(fpath("media", "web", "")), fCompose + "  high:\n    image: x\n    user: \"1000:60001\"\n", "", "service high: compose user: gid 60001 is in 60000-60999"},
		{"gid_env default", hdrHead + opts(puidOpt, "{key: pgid, label: G, type: int, default: 60005}", fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), "", "pgid", "whose default 60005 is in 60000-60999"},
	})
}

func TestJoinsGroup(t *testing.T) {
	folderCases(t, []settingsCase{
		{"gid_env without runs_as.gid_env", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, joins_group: gid_env}")), "", "media", "joins_group: gid_env needs runs_as.gid_env"},
		{"sudo", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, joins_group: sudo}")), "", "media", `folder.joins_group "sudo" must be group_add, gid_env or template`},
		{"gid_env ok", hdrHead + opts(puidOpt, pgidOpt, fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")), "", "", ""},
		{"template ok", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, joins_group: template}")), "", "", ""},
	})
}

func TestMustOwnWritersOnly(t *testing.T) {
	folderCases(t, []settingsCase{
		{"read", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}, must_own: true}")), "", "media", "folder.must_own needs access: write"},
		{"write", hdrHead + opts(fpath("media", "web", ", folder: {access: write, runs_as: {uid: 1000, gid: 1000}, must_own: true}")), "", "", ""},
	})
}

func TestFolderReplacesModeNeedsWritesAs(t *testing.T) {
	for _, f := range []string{"mode: rw", "needs: write", "writes_as: {uid: 1, gid: 1}"} {
		folderCases(t, []settingsCase{
			{f, hdrHead + opts(fpath("media", "web", ", "+f+rw)), "", "media", "folder.access and folder.runs_as replace them"},
		})
	}
}

func TestSameEnvSameRunsAs(t *testing.T) {
	a := fpath("movies", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
	b := fpath("tv", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")
	same := fpath("tv", "web", ", folder: {access: write, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
	other := fpath("tv", "fixed", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")
	folderCases(t, []settingsCase{
		{"differ", hdrHead + opts(puidOpt, pgidOpt, a, b), "", "tv", "names gid_env PGID like setting movies on service web, with another runs_as or joins_group"},
		{"identical", hdrHead + opts(puidOpt, pgidOpt, a, same), "", "", ""},
		{"other service", hdrHead + opts(puidOpt, pgidOpt, a, other), "", "", ""},
	})
}

func TestUIDFromReserved(t *testing.T) {
	folderCases(t, []settingsCase{
		{"uid_from", hdrHead + opts(fpath("media", "web", ", folder: {access: write, runs_as: {uid_from: person_uid, gid: 0}}")), "", "media", "folder.runs_as.uid_from needs file sharing (project 3)"},
		{"gid_from", hdrHead + opts(fpath("media", "web", ", folder: {access: write, runs_as: {uid: 0, gid_from: person_gid}}")), "", "media", "folder.runs_as.gid_from needs file sharing (project 3)"},
	})
	if f := ReservedFeature(&Option{Type: TypePath, Folder: &FolderSpec{RunsAs: &RunsAs{UIDFrom: "x"}}}); f != FeatureFileSharing {
		t.Errorf("ReservedFeature(uid_from) = %q", f)
	}
	if f := ReservedFeature(&Option{Type: TypePath, Folder: &FolderSpec{Access: FolderRead}, Checks: []Check{{Kind: CheckExclusive}}}); f != "" {
		t.Errorf("ReservedFeature(folder, checks) = %q", f)
	}
}

func TestChecksCatalog(t *testing.T) {
	const reason = ", reason: macOS clients store metadata in extended attributes"
	ck := func(c string) string { return ", checks: [{" + c + "}]" }
	personOpt := func(extra string) string {
		return "{key: quota, label: Q, type: int, scope: person, default: 1, resolve: max, delivery: [{header: {name: X-Forwarded-Attr-Quota}}]" + extra + "}"
	}
	folderCases(t, []settingsCase{
		{"unknown kind", hdrHead + opts(fpath("media", "web", rw+ck("kind: quota"+reason))), "", "media", `checks[0]: unknown kind "quota" (the catalog: exclusive, filesystem, free_space, requires_group_value)`},
		{"lan_only", hdrHead + opts(fpath("media", "web", rw+ck("kind: lan_only"+reason))), "", "media", "set lan_only: true on the port"},
		{"no reason", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem, needs: [acl]"))), "", "media", "checks[0] (filesystem): reason must be one line of 1-200 characters"},
		{"long reason", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem, needs: [acl], reason: "+strings.Repeat("a", 201)))), "", "media", "reason must be one line of 1-200 characters"},
		{"newline reason", hdrHead + opts(fpath("media", "web", rw+ck(`kind: filesystem, needs: [acl], reason: "a\nb"`))), "", "media", "reason must be one line"},
		{"200 ok", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem, needs: [acl], reason: "+strings.Repeat("é", 200)))), "", "", ""},
		{"filesystem ok", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem, needs: [acl, xattr], not: [nfs]"+reason))), "", "", ""},
		{"needs posix", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem, needs: [posix]"+reason))), "", "media", `checks[0] (filesystem): needs "posix" must be xattr or acl`},
		{"not ext4", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem, not: [ext4]"+reason))), "", "media", `not "ext4" must be nfs, cifs or fuse`},
		{"needs twice", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem, needs: [acl, acl]"+reason))), "", "media", `needs "acl" listed twice`},
		{"filesystem empty", hdrHead + opts(fpath("media", "web", rw+ck("kind: filesystem"+reason))), "", "media", "filesystem needs needs or not"},
		{"filesystem no folder", hdrHead + opts(fpath("media", "web", ck("kind: filesystem, needs: [acl]"+reason))), "", "media", "checks[0] (filesystem): needs a path option with a folder block"},
		{"exclusive read", hdrHead + opts(fpath("media", "web", rw+ck("kind: exclusive"+reason))), "", "media", "checks[0] (exclusive): needs a path option with folder.access: write"},
		{"exclusive write", hdrHead + opts(fpath("media", "web", ", folder: {access: write, runs_as: {uid: 1, gid: 1}}"+ck("kind: exclusive"+reason))), "", "", ""},
		{"exclusive param", hdrHead + opts(fpath("media", "web", ", folder: {access: write, runs_as: {uid: 1, gid: 1}}"+ck("kind: exclusive, min: 1GiB"+reason))), "", "media", "checks[0] (exclusive): exclusive takes no min"},
		{"free_space ok", hdrHead + opts(fpath("media", "web", rw+ck("kind: free_space, min: 500GiB"+reason))), "", "", ""},
		{"free_space no folder ok", hdrHead + opts(fpath("media", "web", ck("kind: free_space, min: 500GiB"+reason))), "", "", ""},
		{"free_space lots", hdrHead + opts(fpath("media", "web", rw+ck("kind: free_space, min: lots"+reason))), "", "media", `checks[0] (free_space): min "lots"`},
		{"free_space GB", hdrHead + opts(fpath("media", "web", rw+ck("kind: free_space, min: 500GB"+reason))), "", "media", `min "500GB"`},
		{"free_space zero", hdrHead + opts(fpath("media", "web", rw+ck("kind: free_space, min: 0GiB"+reason))), "", "media", "min must be more than 0"},
		{"free_space no min", hdrHead + opts(fpath("media", "web", rw+ck("kind: free_space"+reason))), "", "media", "checks[0] (free_space): free_space needs min"},
		{"free_space on string", hdrHead + opts("{key: theme, label: T, type: string"+ck("kind: free_space, min: 1GiB"+reason)+"}"), hdrCompose, "theme", "checks[0] (free_space): needs a path option"},
		{"requires_group_value instance", hdrHead + opts("{key: theme, label: T, type: string"+ck("kind: requires_group_value"+reason)+"}"), hdrCompose, "theme", "checks[0] (requires_group_value): needs scope: person"},
		{"requires_group_value person", hdrHead + opts(personOpt(ck("kind: requires_group_value"+reason))), "", "", ""},
		{"kind twice", hdrHead + opts(fpath("media", "web", rw+", checks: [{kind: free_space, min: 1GiB"+reason+"}, {kind: free_space, min: 2GiB"+reason+"}]")), "", "media", "checks[1] (free_space): listed twice"},
		{"unknown field", hdrHead + opts(fpath("media", "web", rw+ck("kind: free_space, min: 1GiB, max: 2GiB"+reason))), "", "", "max"},
	})
	if len(CheckKinds) != 4 || CheckKinds[CheckLANOnly] {
		t.Errorf("CheckKinds = %v", CheckKinds)
	}
}

func TestReservedVarFolderPrefix(t *testing.T) {
	if !ReservedVar("PORTCULLIS_FOLDER_GID_X") || !ReservedVar(FolderUIDVar("movies_path")) {
		t.Error("PORTCULLIS_FOLDER_* not reserved")
	}
	if g, u := FolderGIDVar("movies_path"), FolderUIDVar("movies_path"); g != "PORTCULLIS_FOLDER_GID_MOVIES_PATH" || u != "PORTCULLIS_FOLDER_UID_MOVIES_PATH" {
		t.Errorf("vars = %s, %s", g, u)
	}
}

func TestFolderHelpers(t *testing.T) {
	o := &Option{}
	if o.FolderAccess() != "" {
		t.Error("FolderAccess without a block")
	}
	o.Folder = &FolderSpec{Access: FolderWrite}
	if o.FolderAccess() != FolderWrite || o.Folder.Join() != JoinGroupAdd {
		t.Errorf("access %q join %q", o.FolderAccess(), o.Folder.Join())
	}
	o.Folder.JoinsGroup = JoinTemplate
	if o.Folder.Join() != JoinTemplate {
		t.Error("Join")
	}
}

func TestLanOnlyPort(t *testing.T) {
	tp, err := build("app", "src", "", []byte(hdrHead+"ports:\n  - {key: SMB, label: SMB, container: 445, default: 445, protocol: tcp, service: web, lan_only: true}\n  - {key: WEB, label: W, container: 80, default: 8080, protocol: tcp, service: web}\n"),
		[]byte(strings.Replace(hdrCompose, "    labels:\n", "    ports:\n      - \"${SMB_BIND:-0.0.0.0}:${SMB:-445}:445\"\n      - \"${WEB_BIND:-0.0.0.0}:${WEB:-8080}:80\"\n    labels:\n", 1)), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !tp.Manifest.Ports[0].LanOnly || tp.Manifest.Ports[1].LanOnly {
		t.Errorf("ports = %+v", tp.Manifest.Ports)
	}
}
