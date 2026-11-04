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
	"  named:\n    image: x\n    user: www-data\n"

// fComposeEnvUser adds a service whose user: takes both ids from
// PUID/PGID (the fixture must declare them as int options).
const fComposeEnvUser = fCompose + "  envuser:\n    image: x\n    user: \"${PUID:-1000}:${PGID:-1000}\"\n"

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
		{"env form", hdrHead + opts(puidOpt, pgidOpt, fpath("media", "envuser", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), fComposeEnvUser, "", ""},
		{"env user, numbers", hdrHead + opts(puidOpt, pgidOpt, fpath("media", "envuser", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")), fComposeEnvUser, "media", "folder.runs_as.uid: service envuser's compose user: takes it from ${PUID}: use uid_env: PUID"},
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

// Fix round 1 (review I1, I2, M1–M3; security-hook rulings).

// fComposeNoEnvUser is fCompose without the ${PGID} user: (which would
// itself refuse a PGID option defaulting into the folder range).
var fComposeNoEnvUser = fCompose

func TestFolderGIDDefaultsRead(t *testing.T) {
	g := ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}"
	folderCases(t, []settingsCase{
		{"string default", hdrHead + opts(puidOpt, "{key: pgid, label: G, type: int, default: '60001'}", fpath("media", "web", g)), fComposeNoEnvUser, "media", "whose default 60001 is in 60000-60999"},
		{"float default", hdrHead + opts(puidOpt, "{key: pgid, label: G, type: int, default: 60001.0}", fpath("media", "web", g)), fComposeNoEnvUser, "media", "whose default 60001 is in 60000-60999"},
		{"unreadable default", hdrHead + opts(puidOpt, fpath("media", "web", g), "{key: pgid, label: G, type: int, default: lots}"), fComposeNoEnvUser, "media", `folder.runs_as.gid_env PGID names setting pgid, whose default "lots" is not a whole number`},
		{"string default ok", hdrHead + opts(puidOpt, "{key: pgid, label: G, type: int, default: '1000'}", fpath("media", "web", g)), fComposeNoEnvUser, "", ""},
		{"writes_as ref in range", hdrHead + opts("{key: pgid, label: G, type: int, default: 60001}", fpath("media", "web", ", writes_as: {uid: 0, gid: pgid}")), fComposeNoEnvUser, "media", "writes_as.gid: setting pgid's default 60001 is in 60000-60999 (shared folder groups)"},
		{"writes_as ref string", hdrHead + opts("{key: pgid, label: G, type: string, default: 'x'}", fpath("media", "web", ", writes_as: {uid: 0, gid: pgid}")), fComposeNoEnvUser, "media", `writes_as.gid: setting pgid's default "x" is not a whole number`},
		{"writes_as ref ok", hdrHead + opts("{key: pgid, label: G, type: string, default: '1000'}", fpath("media", "web", ", writes_as: {uid: 0, gid: pgid}")), fComposeNoEnvUser, "", ""},
	})
}

func TestComposeGIDDefaultsRefused(t *testing.T) {
	// XG, G and U are instance int options (follow-up 3: a reference must
	// name one); the refs service interpolates them.
	refs := "  refs:\n    image: x\n    environment:\n      XG: ${XG:-}\n      G: ${G:-}\n      U: ${U:-}\n      NAME: ${NAME:-}\n"
	svc := func(extra string) string { return fComposeNoEnvUser + refs + "  extra:\n    image: x\n" + extra }
	ints := []string{"{key: xg, label: XG, type: int}", "{key: g, label: G, type: int}", "{key: u, label: U, type: int}"}
	p := hdrHead + opts(ints[0], ints[1], ints[2], fpath("media", "web", ""))
	withString := hdrHead + opts(ints[0], ints[1], ints[2], "{key: name, label: N, type: string}", fpath("media", "web", ""))
	folderCases(t, []settingsCase{
		{"uid undeclared", p, svc("    user: \"${NOPE}:1000\"\n"), "", "service extra: compose user: uid ${NOPE} must name an instance int option of this template (not a string option, an undeclared variable or PORTCULLIS_*)"},
		{"gid undeclared", p, svc("    user: \"1000:$NOPE\"\n"), "", "service extra: compose user: gid ${NOPE} must name an instance int option of this template"},
		{"gid string option", withString, svc("    user: \"1000:${NAME}\"\n"), "", "compose user: gid ${NAME} must name an instance int option"},
		{"uid string option", withString, svc("    user: \"${NAME}\"\n"), "", "compose user: uid ${NAME} must name an instance int option"},
		{"gid portcullis", p, svc("    user: \"1000:${PORTCULLIS_INSTANCE}\"\n"), "", "compose user: gid ${PORTCULLIS_INSTANCE} must name an instance int option"},
		{"group_add undeclared", p, svc("    group_add: [\"${NOPE:-1000}\"]\n"), "", "service extra: group_add ${NOPE} must name an instance int option of this template"},
		{"group_add string option", withString, svc("    group_add: [$NAME]\n"), "", "group_add ${NAME} must name an instance int option"},
		{"user :- default", p, svc("    user: \"1000:${XG:-60001}\"\n"), "", "service extra: compose user: gid 60001 (the default of ${XG}) is in 60000-60999 (shared folder groups)"},
		{"user - default", p, svc("    user: \"1000:${XG-60002}\"\n"), "", "gid 60002 (the default of ${XG}) is in 60000-60999"},
		{"user option default", hdrHead + opts("{key: pgid, label: G, type: int, default: 60003}", fpath("media", "web", "")), svc("    user: \"1000:${PGID:-1000}\"\n"), "", "service extra: compose user: gid ${PGID} is setting pgid, whose default 60003 is in 60000-60999 (shared folder groups)"},
		{"user ok", p, svc("    user: \"1000:${XG:-1000}\"\n"), "", ""},
		{"group_add literal", p, svc("    group_add: [\"60001\"]\n"), "", "service extra: group_add gid 60001 is in 60000-60999 (shared folder groups)"},
		{"group_add int", p, svc("    group_add: [10001, 60999]\n"), "", "service extra: group_add gid 60999 is in 60000-60999"},
		{"group_add default", p, svc("    group_add: [\"${G:-60500}\"]\n"), "", "service extra: group_add gid 60500 (the default of ${G}) is in 60000-60999"},
		{"group_add option default", hdrHead + opts("{key: pgid, label: G, type: int, default: 60004}", fpath("media", "web", "")), svc("    group_add: [\"${PGID}\"]\n"), "", "service extra: group_add ${PGID} is setting pgid, whose default 60004 is in 60000-60999"},
		{"group_add names ok", p, svc("    group_add: [video, \"10001\", \"${G-1000}\", $G]\n"), "", ""},
		{"group_add plus", p, svc("    group_add: [\"${G:+1000}\"]\n"), "", `group_add entry "${G:+1000}" must be`},
		{"group_add plus bare", p, svc("    group_add: [\"${G+1000}\"]\n"), "", `group_add entry "${G+1000}" must be`},
		{"group_add escaped", p, svc("    group_add: [\"$${G:-60500}\"]\n"), "", `service extra: group_add entry "$${G:-60500}" must be a whole number, a group name or exactly one ${NAME} / $NAME (no mixed forms)`},
		{"group_add mixed", p, svc("    group_add: [\"${X:-6}0001\"]\n"), "", `service extra: group_add entry "${X:-6}0001" must be a whole number, a group name or exactly one ${NAME} / $NAME (no mixed forms)`},
		{"group_add nested", p, svc("    group_add: [\"${X:-${Y:-60001}}\"]\n"), "", `group_add entry "${X:-${Y:-60001}}" must be`},
		{"user mixed", p, svc("    user: \"1000:${X:-6}0001\"\n"), "", `service extra: compose user: gid "${X:-6}0001" must be a whole number or exactly one ${NAME} / $NAME (no mixed forms)`},
		{"user two refs", p, svc("    user: \"1000:${A}${B}\"\n"), "", `compose user: gid "${A}${B}" must be`},
		{"group_add text fallback", p, svc("    group_add: [\"${G:-abc}\"]\n"), "", `group_add entry "${G:-abc}" must be`},
		{"group_add empty fallback", p, svc("    group_add: [\"${G:-}\"]\n"), "", `group_add entry "${G:-}" must be`},
		{"group_add $ fallback", p, svc("    group_add: [\"${G:-$H}\"]\n"), "", `group_add entry "${G:-$H}" must be`},
		{"group_add error form", p, svc("    group_add: [\"${G:?unset}\"]\n"), "", `group_add entry "${G:?unset}" must be`},
		{"user forms ok", p, svc("    user: \"${U}:${XG-1000}\"\n"), "", ""},
		{"user plus", p, svc("    user: \"1000:${XG:+1000}\"\n"), "", `compose user: gid "${XG:+1000}" must be`},
		{"user plus in range", p, svc("    user: \"1000:${XG+60001}\"\n"), "", `compose user: gid "${XG+60001}" must be`},
		{"uid mixed", p, svc("    user: \"${X:-6}0001:1000\"\n"), "", `service extra: compose user: uid "${X:-6}0001" must be a whole number, a user name or exactly one ${NAME} / $NAME (no mixed forms)`},
		{"uid plus", p, svc("    user: \"${X:+0}\"\n"), "", `compose user: uid "${X:+0}" must be`},
		{"uid colon fallback", p, svc("    user: \"${A:-1:60001}\"\n"), "", `service extra: compose user: "${A:-1:60001}": a ${…} fallback may only be a whole number (no ':', '$' or nesting)`},
		{"uid dollar fallback", p, svc("    user: \"${A:-$B}:1000\"\n"), "", `a ${…} fallback may only be a whole number`},
		{"unterminated", p, svc("    user: \"${A:-1\"\n"), "", `a ${…} fallback may only be a whole number`},
		{"uid name ok", p, svc("    user: www-data\n"), "", ""},
		{"uid forms ok", p, svc("    user: \"${U-1000}:${G:-1000}\"\n"), "", ""},
		{"uid bare ok", p, svc("    user: \"$U:1000\"\n"), "", ""},
		{"user text fallback", p, svc("    user: \"1000:${XG:-x}\"\n"), "", `compose user: "1000:${XG:-x}": a ${…} fallback may only be a whole number`},
		{"user gid name", p, svc("    user: \"1000:staff\"\n"), "", `compose user: gid "staff" must be`},
		{"group_add not a list", p, svc("    group_add: \"60001\"\n"), "", "service extra: group_add must be a list"},
	})
}

func TestFolderServiceReferencesResolve(t *testing.T) {
	m := hdrHead + opts(puidOpt, pgidOpt, fpath("media", "extra", rw))
	svc := func(extra string) string { return fCompose + "  extra:\n    image: x\n" + extra }
	folderCases(t, []settingsCase{
		{"unknown ref", m, svc("    group_add: [\"${NOPE:-1000}\"]\n"), "", "service extra: group_add ${NOPE} must name an instance int option of this template"},
		{"named group", m, svc("    group_add: [video]\n"), "media", `group_add entry "video" next to a folder block must be a number`},
		{"mixed", m, svc("    group_add: [\"1${PGID}\"]\n"), "", `group_add entry "1${PGID}" must be a whole number, a group name or exactly one`},
		{"option ref ok", m, svc("    group_add: [\"${PGID:-1000}\", \"10001\", 44]\n"), "", ""},
		{"named group without folder", hdrHead + opts(fpath("media", "extra", "")), svc("    group_add: [video]\n"), "", ""},
	})
}

func TestGIDEnvJoinOwnsService(t *testing.T) {
	a := fpath("movies", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
	num := fpath("tv", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")
	numFirst := fpath("tv", "web", ", folder: {access: read, runs_as: {uid: 1000, gid: 1000}}")
	b := fpath("movies", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
	folderCases(t, []settingsCase{
		{"numeric after gid_env join", hdrHead + opts(puidOpt, pgidOpt, a, num), "", "tv", "service web joins a folder group through gid_env PGID: every folder option on it must use runs_as.gid_env PGID (setting tv doesn't)"},
		{"gid_env join after numeric", hdrHead + opts(puidOpt, pgidOpt, numFirst, b), "", "movies", "service web joins a folder group through gid_env PGID: every folder option on it must use runs_as.gid_env PGID (setting tv doesn't)"},
	})
}

func TestRunsAsNonIntegerFriendly(t *testing.T) {
	folderCases(t, []settingsCase{
		{"string uid", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: abc, gid: 1}}")), "", "", `folder.runs_as.uid: want a whole number, not "abc" (a variable goes in uid_env)`},
		{"float gid", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 1, gid: 1.5}}")), "", "", `folder.runs_as.gid: want a whole number, not "1.5" (a variable goes in gid_env)`},
		{"hex ok", hdrHead + opts(fpath("media", "web", ", folder: {access: read, runs_as: {uid: 0x10, gid: 1}}")), "", "", ""},
	})
}

func TestEffectiveMode(t *testing.T) {
	for _, c := range []struct {
		o    Option
		want string
	}{
		{Option{Mode: "ro"}, "ro"},
		{Option{Mode: "rw"}, "rw"},
		{Option{}, "rw"},
		{Option{Folder: &FolderSpec{Access: FolderRead}}, "ro"},
		{Option{Folder: &FolderSpec{Access: FolderWrite}}, "rw"},
		{Option{Mode: "rw", Folder: &FolderSpec{Access: FolderRead}}, "ro"},
	} {
		if got := c.o.EffectiveMode(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.o, got, c.want)
		}
	}
}

// groupAddResolves applies the same strict forms: an option name with a
// non-numeric fallback is not resolved (security review).
func TestGroupAddResolvesStrictForms(t *testing.T) {
	m := &Manifest{Settings: &SettingsSpec{Options: []Option{{Key: "pgid", Type: TypeInt}}}}
	for e, ok := range map[string]bool{
		"${PGID}": true, "$PGID": true, "${PGID:-1000}": true, "${PGID-1000}": true, "1000": true, "${PGID:+1000}": false, "${PGID+1000}": false,
		"${PGID:-abc}": false, "${PGID:-$X}": false, "${PGID:-${X}}": false, "${PGID?e}": false, "${NOPE}": false, "video": false, "x${PGID}": false,
	} {
		v := &specCheck{m: m, groupAdd: map[string][]string{"s": {e}}}
		if err := v.groupAddResolves("s"); (err == nil) != ok {
			t.Errorf("%q: %v, want ok=%v", e, err, ok)
		}
	}
}

// Follow-up 3 (re-review "New Breakage").

func TestComposeIDsForms(t *testing.T) {
	refs := "  refs:\n    image: x\n    environment:\n      FIRST: ${FIRST:-}\n      SECOND: ${SECOND:-}\n"
	svc := func(extra string) string { return fComposeNoEnvUser + refs + "  extra:\n    image: x\n" + extra }
	two := func(def string) string {
		return hdrHead + opts("{key: g2, label: G, type: int"+def+", delivery: [{env: FIRST}, {env: SECOND}]}", fpath("media", "web", ""))
	}
	anchors := "x-u: &u \"1000:60001\"\nx-g: &g \"60002\"\n"
	folderCases(t, []settingsCase{
		{"aliased user", two(""), anchors + svc("    user: *u\n"), "", "service extra: compose user: gid 60001 is in 60000-60999"},
		{"aliased group_add entry", two(""), anchors + svc("    group_add: [*g]\n"), "", "service extra: group_add gid 60002 is in 60000-60999"},
		{"octal group_add", two(""), svc("    group_add: [0165141]\n"), "", "service extra: group_add gid 60001 is in 60000-60999"},
		{"octal user", two(""), svc("    user: 0165141\n"), "", ""},
		{"second env delivery ok", two(""), svc("    user: \"1000:${SECOND}\"\n    group_add: [$SECOND]\n"), "", ""},
		{"second env delivery default", two(", default: 60003"), svc("    group_add: [\"${SECOND}\"]\n"), "", "service extra: group_add ${SECOND} is setting g2, whose default 60003 is in 60000-60999"},
	})
}

// The folder gid range is a gid rule: uid sources in it are not refused
// (as for a numeric runs_as.uid).
func TestUIDDefaultsNotRangeChecked(t *testing.T) {
	folderCases(t, []settingsCase{
		{"uid_env default", hdrHead + opts("{key: puid, label: P, type: int, default: 60001}", pgidOpt, fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), fComposeNoEnvUser, "", ""},
		{"writes_as uid key", hdrHead + opts("{key: puid, label: P, type: int, default: 60001}", fpath("media", "web", ", writes_as: {uid: puid, gid: 0}")), fComposeNoEnvUser, "", ""},
		{"uid_env second delivery", hdrHead + opts("{key: puid, label: P, type: int, default: 1000, delivery: [{env: OTHER_UID}, {env: PUID}]}", pgidOpt, fpath("media", "web", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")), strings.Replace(fComposeNoEnvUser, "    environment:\n", "    environment:\n      OTHER_UID: ${OTHER_UID:-}\n", 1), "", ""},
	})
}

func TestComposeIDsDecodeError(t *testing.T) {
	if _, _, err := composeIDs([]byte("services:\n  a: [1, 2]\n")); err == nil {
		t.Error("a service that isn't a mapping decoded")
	}
}

// Fix round 5: !!binary scalars are refused (compose decodes
// [!!binary MDYwMDAx] to "060001", gid 60001).
func TestBinaryTagRefused(t *testing.T) {
	svc := func(extra string) string { return fCompose + "  extra:\n    image: x\n" + extra }
	p := hdrHead + opts(fpath("media", "web", ""))
	folderCases(t, []settingsCase{
		{"group_add", p, svc("    group_add: [!!binary MDYwMDAx]\n"), "", "YAML tag !!binary is not allowed"},
		{"user", p, svc("    user: !!binary MTAwMDowNjAwMDE=\n"), "", "YAML tag !!binary is not allowed"},
		{"manifest", hdrHead + "description: !!binary aGk=\n" + opts(fpath("media", "web", "")), fCompose, "", "YAML tag !!binary is not allowed"},
	})
	for _, c := range []string{
		"services:\n  s:\n    group_add: [!!binary MDYwMDAx]\n",
		"services:\n  s:\n    user: !!binary MTAwMDowNjAwMDE=\n",
		"services:\n  s:\n    user: !!float 1000\n",
	} {
		if _, _, err := composeIDs([]byte(c)); err == nil {
			t.Errorf("composeIDs accepted %q", c)
		}
	}
	if _, _, err := composeIDs([]byte("services:\n  s:\n    user: !!str 1000\n    group_add: [!!int 10001, !!null ~]\n")); err == nil {
		t.Error("a null group_add entry accepted")
	}
	if u, _, err := composeIDs([]byte("services:\n  s:\n    user: !!str 1000\n")); err != nil || u["s"] != "1000" {
		t.Errorf("!!str user = %v, %v", u, err)
	}
}

// GIDRefs: every option a gid reference names (ruling 30), never a uid
// source.
func TestGIDRefs(t *testing.T) {
	gid := 1001
	m := &Manifest{Settings: &SettingsSpec{Options: []Option{
		{Key: "puid", Type: TypeInt, Delivery: []Delivery{{Env: "PUID"}}},
		{Key: "pgid", Type: TypeInt, Delivery: []Delivery{{Env: "PGID"}}},
		{Key: "extra", Type: TypeInt, Delivery: []Delivery{{Env: "EXTRA_GID"}}},
		{Key: "owner", Type: TypeString},
		{Key: "media", Type: TypePath, Folder: &FolderSpec{Access: FolderRead, RunsAs: &RunsAs{UIDEnv: "PUID", GIDEnv: "PGID"}}},
		{Key: "data", Type: TypePath, WritesAs: &Owner{UID: OwnerRef{Key: "puid"}, GID: OwnerRef{Key: "owner"}}},
		{Key: "logs", Type: TypePath, WritesAs: &Owner{UID: OwnerRef{Num: &gid}, GID: OwnerRef{Num: &gid}}},
	}}}
	compose := []byte("services:\n  a:\n    user: \"${PUID:-1000}:${PGID:-1000}\"\n  b:\n    group_add: [\"${EXTRA_GID}\", \"100\"]\n")
	got, err := GIDRefs(m, compose)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"pgid": "folder.runs_as.gid_env of media", "owner": "writes_as.gid of data", "extra": "group_add of service b"}
	if len(got) != len(want) {
		t.Fatalf("refs = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("refs[%s] = %q, want %q", k, got[k], v)
		}
	}
	if _, err := GIDRefs(m, []byte("services:\n  a: [1]\n")); err == nil {
		t.Error("bad compose accepted")
	}
}

// Fix round 1, I3: a gid_env join's variable may be read only by the
// services the folder options target.
func TestGIDEnvJoinVariableNotShared(t *testing.T) {
	join := fpath("movies", "envuser", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}")
	m := hdrHead + opts(puidOpt, pgidOpt, join)
	folderCases(t, []settingsCase{
		{"alone", m, fComposeEnvUser, "", ""},
		{"sidecar group_add", m, fComposeEnvUser + "  side:\n    image: x\n    group_add: [\"${PGID}\"]\n", "movies",
			"folder.joins_group: gid_env writes the folder gid to PGID, which service side's group_add also reads: only the services the folder options target may use a gid_env variable"},
		{"sidecar user", m, fComposeEnvUser + "  side:\n    image: x\n    user: \"${PUID:-1000}:${PGID:-1000}\"\n", "movies",
			"folder.joins_group: gid_env writes the folder gid to PGID, which service side's compose user: gid also reads: only the services the folder options target may use a gid_env variable"},
		{"group_add join elsewhere ok", hdrHead + opts(puidOpt, pgidOpt, fpath("movies", "envuser", ", folder: {access: read, runs_as: {uid_env: PUID, gid_env: PGID}}")),
			fComposeEnvUser + "  side:\n    image: x\n    group_add: [\"${PGID}\"]\n", "", ""},
	})
}
