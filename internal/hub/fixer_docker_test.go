//go:build docker

package hub

// Integration tests of the started fixer helper against a real Docker
// daemon: `go test -tags docker -run TestDocker ./internal/hub/`. They
// build an image shaped like the Hub's (same base, USER 10001, a wget
// HEALTHCHECK, ENTRYPOINT ["hub"]) around this tree's binary, so the
// overrides of ruling 19 are exercised, and run the real `hub folderfix`
// on a Docker volume's directory bound like a shared folder. Skipped
// without a daemon or the docker CLI, unless PORTCULLIS_DOCKER_TEST=require
// (CI), where that is a failure.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/state"
)

func dockerOrSkip(t *testing.T) *docker.Client {
	t.Helper()
	skip := func(format string, args ...any) {
		if os.Getenv("PORTCULLIS_DOCKER_TEST") == "require" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skip("no docker CLI: %v", err)
	}
	c, err := docker.New(os.Getenv("DOCKER_HOST"))
	if err != nil {
		skip("docker: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		skip("no Docker daemon: %v", err)
	}
	return c
}

func dockerCLI(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

var (
	fixerImageOnce sync.Once
	fixerImageID   string
	fixerImageErr  error
)

// buildFixerImage builds the test image once per test binary.
func buildFixerImage(t *testing.T) string {
	t.Helper()
	fixerImageOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fixerimg")
		if err != nil {
			fixerImageErr = err
			return
		}
		defer os.RemoveAll(dir)
		arch, err := exec.Command("docker", "version", "--format", "{{.Server.Arch}}").Output()
		if err != nil {
			fixerImageErr = fmt.Errorf("server arch: %v", err)
			return
		}
		build := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(dir, "hub"), "github.com/portcullis/hub/cmd/hub")
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)))
		if out, err := build.CombinedOutput(); err != nil {
			fixerImageErr = fmt.Errorf("go build: %v\n%s", err, out)
			return
		}
		df := "FROM " + HelperImage + "\nCOPY hub /usr/local/bin/hub\nUSER 10001:10001\n" +
			"HEALTHCHECK --interval=1s CMD wget -q -O /dev/null http://127.0.0.1:8888/healthz || exit 1\nENTRYPOINT [\"hub\"]\n"
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o644); err != nil {
			fixerImageErr = err
			return
		}
		tag := "portcullis-hub-fixertest:local"
		if out, err := exec.Command("docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
			fixerImageErr = fmt.Errorf("docker build: %v\n%s", err, out)
			return
		}
		id, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", tag).Output()
		fixerImageID, fixerImageErr = strings.TrimSpace(string(id)), err
	})
	if fixerImageErr != nil {
		t.Fatal(fixerImageErr)
	}
	return fixerImageID
}

// testFolder makes a Docker volume shaped like a shared folder (dirs 0750
// and files 0640 owned by 1000:1000 below a root-owned root) and returns
// the host path of its directory.
func testFolder(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("pcfixtest-%d", time.Now().UnixNano())
	dockerCLI(t, "volume", "create", name)
	t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", name).Run() })
	dockerCLI(t, "run", "--rm", "--network", "none", "-v", name+":/v", HelperImage, "sh", "-c",
		"mkdir -p /v/a/b && echo x > /v/a/f && echo y > /v/a/b/g && chown -R 1000:1000 /v/a && "+
			"chmod 0750 /v/a /v/a/b && chmod 0640 /v/a/f /v/a/b/g && chown 0:0 /v && chmod 0755 /v")
	return dockerCLI(t, "volume", "inspect", "--format", "{{.Mountpoint}}", name)
}

func dockerHub(t *testing.T, c *docker.Client) *Hub {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0o755)
	if err := state.New().Save(filepath.Join(data, "state.yaml")); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{ProjectDir: root, DataDir: data}, newFakeRunner(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.fixerImage = buildFixerImage(t)
	return h
}

var testTarget = folderfix.Target{GID: 60001, Files: "rw"}

func scanFolder(t *testing.T, h *Hub, src string, o folderfix.Options) *folderfix.Report {
	t.Helper()
	o.Target = testTarget
	// A first scan learns the identity: a path check (H5: a folder scan
	// checks dev, ino and mount root).
	folder := "dockertest"
	if o.ExpectDev == 0 {
		folder = ""
	}
	rep, err := h.runFixer(context.Background(), fixerRun{Mode: "scan", Folder: folder, Source: src, Opts: o})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return rep
}

func checkedOpts(s *folderfix.Report) folderfix.Options {
	return folderfix.Options{ExpectDev: s.Dev, ExpectIno: s.Ino, ExpectMountRoot: s.MountRoot, Target: testTarget}
}

func conforms(r *folderfix.Report) bool {
	e := r.Expected
	return e != nil && e.Group.N == 0 && e.Setgid.N == 0 && e.DefaultACL.N == 0 && e.Mode.N == 0 && e.Owner.N == 0 && r.Plan.Changes == 0
}

// scan → snapshot → apply → verify → restore through runFixer, the way
// the Hub runs them.
func TestDockerFixerEndToEnd(t *testing.T) {
	c := dockerOrSkip(t)
	h := dockerHub(t, c)
	src := testFolder(t)
	ctx := context.Background()

	s := scanFolder(t, h, src, folderfix.Options{})
	if s.Plan == nil || s.Plan.Changes != 5 || s.Dev == 0 || s.MountRoot == "" {
		t.Fatalf("scan = %+v", s)
	}
	if !slices.Contains([]string{"ext4", "xfs", "btrfs", "zfs"}, s.FSType) {
		t.Skipf("the volume is on %s: the fixer writes only on ext4/xfs/btrfs/zfs", s.FSType)
	}
	o := checkedOpts(s)
	o.ExpectDigest = s.Plan.Digest

	var snap []byte
	if _, err := h.runFixer(ctx, fixerRun{Mode: "snapshot", Folder: "dockertest", Source: src, Opts: o,
		Out: func(r io.Reader) error { var err error; snap, err = io.ReadAll(r); return err }}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snap) < 20 || snap[0] != 0x1f || snap[1] != 0x8b {
		t.Fatalf("snapshot is no gzip: %d bytes", len(snap))
	}

	// A wrong mount root is a refusal (409) with nothing changed.
	bad := o
	bad.ExpectMountRoot = "/elsewhere"
	if _, err := h.runFixer(ctx, fixerRun{Mode: "apply", Folder: "dockertest", Source: src, Opts: bad, Extra: folderfix.ArgsExtra{Expect: s.Plan.Changes}}); statusOf(err) != 409 {
		t.Errorf("wrong mount root: %v", err)
	}
	a, err := h.runFixer(ctx, fixerRun{Mode: "apply", Folder: "dockertest", Source: src, Opts: o, Extra: folderfix.ArgsExtra{Expect: s.Plan.Changes}})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if a.Changed != s.Plan.Changes || a.Races.N != 0 || a.Failed.N != 0 {
		t.Errorf("apply = changed %d races %d failed %d", a.Changed, a.Races.N, a.Failed.N)
	}
	if v := scanFolder(t, h, src, checkedOpts(s)); !conforms(v) {
		t.Errorf("verify after apply: %+v plan %+v", v.Expected, v.Plan)
	}

	r, err := h.runFixer(ctx, fixerRun{Mode: "restore", Folder: "dockertest", Source: src, Opts: checkedOpts(s),
		In: bytes.NewReader(snap), InSize: int64(len(snap))})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if r.Changed != s.Plan.Changes {
		t.Errorf("restore changed %d, want %d", r.Changed, s.Plan.Changes)
	}
	if v := scanFolder(t, h, src, checkedOpts(s)); v.Plan.Changes != s.Plan.Changes || v.Plan.Digest != s.Plan.Digest {
		t.Errorf("after restore: plan %+v, want the first scan's", v.Plan)
	}

	// No helper is left behind.
	cs, err := c.ListContainers(ctx, docker.Filters{"label": {docker.LabelHelper + "=folder:dockertest"}})
	if err != nil || len(cs) != 0 {
		t.Errorf("leftover helpers: %v, %v", cs, err)
	}
}

// capBits are the capability numbers (linux/capability.h).
var capBits = map[string]uint{"CHOWN": 0, "DAC_OVERRIDE": 1, "DAC_READ_SEARCH": 2, "FOWNER": 3, "FSETID": 4}

// runInHelper runs argv in the helper a fixer run of r would get.
func runInHelper(t *testing.T, c *docker.Client, h *Hub, r fixerRun, argv ...string) *docker.RunResult {
	t.Helper()
	s := r.spec(h.fixerImage)
	s.Cmd = argv
	res, err := c.RunHelper(context.Background(), s, nil)
	if err != nil {
		t.Fatalf("%v: %v", argv, err)
	}
	return res
}

// From inside the helper: exactly the mode's capabilities (effective,
// permitted and bounding), no-new-privileges, uid 0, no network, a
// read-only rootfs, /proc present, no healthcheck process.
func TestDockerFixerIsolation(t *testing.T) {
	c := dockerOrSkip(t)
	h := dockerHub(t, c)
	src := testFolder(t)
	for _, r := range []fixerRun{
		{Mode: "scan", Folder: "dockertest", Source: src},
		{Mode: "apply", Folder: "dockertest", Source: src},
	} {
		var want uint64
		for _, c := range r.spec(h.fixerImage).CapAdd {
			want |= 1 << capBits[c]
		}
		res := runInHelper(t, c, h, r, "/bin/cat", "/proc/self/status", "/proc/net/dev", "/proc/net/route")
		if res.ExitCode != 0 {
			t.Fatalf("%s: cat exit %d: %s", r.Mode, res.ExitCode, res.Stderr)
		}
		st := map[string]string{}
		var ifaces []string
		routes := 0
		sc := bufio.NewScanner(bytes.NewReader(res.Stdout))
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) == 11 && f[0] != "Iface" && !strings.Contains(f[0], ":") {
				routes++ // a /proc/net/route line
			}
			k, v, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			if strings.HasPrefix(k, "Cap") || k == "NoNewPrivs" || k == "Uid" || k == "Gid" || k == "Seccomp" {
				st[k] = strings.TrimSpace(v)
			} else if !strings.Contains(k, "|") && strings.TrimSpace(k) != "" && !strings.HasPrefix(k, "Name") && len(strings.Fields(v)) > 8 {
				ifaces = append(ifaces, strings.TrimSpace(k))
			}
		}
		for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
			got, err := strconv.ParseUint(st[k], 16, 64)
			if err != nil || got != want {
				t.Errorf("%s: %s = %s, want %x", r.Mode, k, st[k], want)
			}
		}
		if st["CapInh"] != "0000000000000000" && st["CapInh"] != "" {
			t.Errorf("%s: CapInh = %s", r.Mode, st["CapInh"])
		}
		if st["NoNewPrivs"] != "1" || strings.Fields(st["Uid"])[1] != "0" || strings.Fields(st["Gid"])[1] != "0" {
			t.Errorf("%s: status = %v", r.Mode, st)
		}
		// network none: lo plus the kernel's fallback tunnel devices of
		// every namespace (sit0, gre0, …; down), no veth, no route.
		if !slices.Contains(ifaces, "lo") || slices.ContainsFunc(ifaces, func(i string) bool {
			return strings.HasPrefix(i, "eth") || strings.HasPrefix(i, "veth") || strings.HasPrefix(i, "en")
		}) || routes != 0 {
			t.Errorf("%s: network interfaces = %v, %d routes", r.Mode, ifaces, routes)
		}
		if res := runInHelper(t, c, h, r, "/bin/touch", "/rootfs-write"); res.ExitCode == 0 {
			t.Errorf("%s: the rootfs is writable", r.Mode)
		}
		// pids 16: the 17th process can't start.
		if res := runInHelper(t, c, h, r, "/bin/sh", "-c", "for i in $(seq 20); do sleep 5 & done; wait"); res.ExitCode == 0 && !strings.Contains(string(res.Stderr), "fork") {
			t.Errorf("%s: 20 processes started under pids 16: %s", r.Mode, res.Stderr)
		}
	}
	// The scan's bind is read-only, the apply's read-write.
	if res := runInHelper(t, c, h, fixerRun{Mode: "scan", Folder: "dockertest", Source: src}, "/bin/touch", "/folder/x"); res.ExitCode == 0 {
		t.Error("scan: /folder is writable")
	}
}

// Each capability an apply gets is needed: without it the apply fails or
// leaves the folder non-conformant. Without CHOWN the group can't change;
// without FOWNER modes and ACLs of entries root doesn't own can't be set;
// without FSETID the kernel drops setgid when root (not in the folder gid)
// chmods a directory; without DAC_READ_SEARCH the 0750 directories of uid
// 1000 can't be read; without DAC_OVERRIDE --mkdir can't create in a
// directory root has no write bit on (and only --mkdir gets it). The
// restore in TestDockerFixerEndToEnd runs with the same set as a plain
// apply.
func TestDockerFixerCapsMinimal(t *testing.T) {
	c := dockerOrSkip(t)
	h := dockerHub(t, c)
	ctx := context.Background()
	for _, mkdir := range []bool{false, true} {
		for _, drop := range []string{"", "CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE", "DAC_READ_SEARCH"} {
			t.Run(fmt.Sprintf("mkdir %v without %s", mkdir, drop), func(t *testing.T) {
				src := testFolder(t)
				s := scanFolder(t, h, src, folderfix.Options{})
				if !slices.Contains([]string{"ext4", "xfs", "btrfs", "zfs"}, s.FSType) {
					t.Skipf("volume on %s", s.FSType)
				}
				o := checkedOpts(s)
				o.ExpectDigest = s.Plan.Digest
				if mkdir {
					o.Target.Mkdir = []string{"a/new"}
				}
				r := fixerRun{Mode: "apply", Folder: "dockertest", Source: src, Opts: o, Extra: folderfix.ArgsExtra{Expect: s.Plan.Changes}}
				if err := r.validate(); err != nil {
					t.Fatal(err)
				}
				spec := r.spec(h.fixerImage)
				spec.CapAdd = slices.DeleteFunc(spec.CapAdd, func(c string) bool { return c == drop })
				res, err := c.RunHelper(ctx, spec, nil)
				if err != nil {
					t.Fatal(err)
				}
				var rep folderfix.Report
				decodeStrict(lastLine(res.Stdout), &rep)
				v := scanFolder(t, h, src, checkedOpts(s))
				ok := res.ExitCode == 0 && rep.Failed.N == 0 && conforms(v)
				t.Logf("mkdir %v without %q: exit %d changed %d failed %d first error %q; verify conforms %v (group %d setgid %d acl %d mode %d)",
					mkdir, drop, res.ExitCode, rep.Changed, rep.Failed.N, first(rep.Errors), conforms(v), v.Expected.Group.N, v.Expected.Setgid.N, v.Expected.DefaultACL.N, v.Expected.Mode.N)
				// With --mkdir, DAC_OVERRIDE also covers reading and
				// searching, so DAC_READ_SEARCH is redundant there only.
				needed := drop == "CHOWN" || drop == "FOWNER" || drop == "FSETID" ||
					(mkdir && drop == "DAC_OVERRIDE") || (!mkdir && drop == "DAC_READ_SEARCH")
				if ok == needed {
					t.Errorf("without %s (mkdir %v): success %v, want %v", drop, mkdir, ok, !needed)
				}
			})
		}
	}
	// Scan without DAC_READ_SEARCH can't read the 0750 directories.
	src := testFolder(t)
	spec := fixerRun{Mode: "scan", Folder: "dockertest", Source: src}.spec(h.fixerImage)
	spec.CapAdd = nil
	res, err := c.RunHelper(ctx, spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rep folderfix.Report
	if err := decodeStrict(lastLine(res.Stdout), &rep); err != nil {
		t.Fatalf("scan report: %v (%s)", err, res.Stderr)
	}
	t.Logf("scan without DAC_READ_SEARCH: exit %d entries %d failed %d first error %q", res.ExitCode, rep.Entries, rep.Failed.N, first(rep.Errors))
	if rep.Failed.N == 0 && len(rep.Errors) == 0 {
		t.Errorf("scan without DAC_READ_SEARCH read everything: %+v", rep)
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return clipRunes(s[0], 160)
}

// R53 on a real daemon: a container's own mountinfo names its full ID, and
// inspecting that ID answers the same ID and its compose labels.
func TestDockerSelfContainerID(t *testing.T) {
	c := dockerOrSkip(t)
	id := dockerCLI(t, "run", "-d", "--network", "none", "--label", "com.docker.compose.project=portcullis",
		"--label", "com.docker.compose.service=hub", HelperImage, "sleep", "60")
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", id).Run() })
	mi := dockerCLI(t, "exec", id, "cat", "/proc/self/mountinfo")
	got, err := selfContainerID([]byte(mi))
	if err != nil || got != id {
		t.Fatalf("selfContainerID = %q, %v; want %q\n%s", got, err, id, mi)
	}
	ci, err := c.InspectContainer(context.Background(), got)
	if err != nil || ci.ID != id || ci.Labels[docker.LabelProject] != coreProject || ci.Labels[docker.LabelService] != hubService || !strings.HasPrefix(ci.Image, "sha256:") {
		t.Errorf("inspect = %+v, %v", ci, err)
	}
}

// treeVolume is a per-person tree in a fresh volume: t (root 0755) with
// alice's directory (20000:100 0700: her own, with the wrong group)
// holding a file (1000:100 0640).
func treeVolume(t *testing.T) (string, string) {
	t.Helper()
	name := fmt.Sprintf("pcfixtree-%d", time.Now().UnixNano())
	dockerCLI(t, "volume", "create", name)
	t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", name).Run() })
	dockerCLI(t, "run", "--rm", "--network", "none", "-v", name+":/v", HelperImage, "sh", "-c",
		"mkdir -p /v/t/alice && echo x > /v/t/alice/f && chown 20000:100 /v/t/alice && chown 1000:100 /v/t/alice/f && chmod 0700 /v/t/alice && chmod 0640 /v/t/alice/f && "+
			"chown 0:0 /v /v/t && chmod 0755 /v /v/t")
	return name, dockerCLI(t, "volume", "inspect", "--format", "{{.Mountpoint}}", name)
}

// F33 on a real daemon: childfix with CHOWN and FOWNER only (the bind
// root read-write at /broot) gives one person's 0700 directory uid:uid
// 0700 and changes nothing inside it; without either capability it
// fails (the contract's measured minimum).
func TestDockerChildFixCaps(t *testing.T) {
	c := dockerOrSkip(t)
	h := dockerHub(t, c)
	ctx := context.Background()
	for _, drop := range []string{"", "CHOWN", "FOWNER"} {
		t.Run("without "+drop, func(t *testing.T) {
			vol, src := treeVolume(t)
			pr, err := h.runProbe(ctx, fixerRun{Mode: "probe", Source: src, Extra: folderfix.ArgsExtra{Rel: "t/alice"}})
			if err != nil || !pr.Exists || pr.RelMountRoot == "" {
				t.Fatalf("probe = %+v, %v", pr, err)
			}
			if !slices.Contains([]string{"ext4", "xfs", "btrfs", "zfs"}, pr.FSType) {
				t.Skipf("volume on %s", pr.FSType)
			}
			r := fixerRun{Mode: "childfix", Source: src,
				Opts:  folderfix.Options{ExpectDev: pr.Dev, ExpectIno: pr.Ino, ExpectMountRoot: pr.RelMountRoot},
				Extra: folderfix.ArgsExtra{Rel: "t", Child: folderfix.ChildFix{Name: "alice", UID: 20000, Owner: 20000}}}
			if err := r.validate(); err != nil {
				t.Fatal(err)
			}
			spec := r.spec(h.fixerImage)
			spec.CapAdd = slices.DeleteFunc(spec.CapAdd, func(c string) bool { return c == drop })
			res, err := c.RunHelper(ctx, spec, nil)
			if err != nil {
				t.Fatal(err)
			}
			var rep folderfix.Report
			decodeStrict(lastLine(res.Stdout), &rep)
			st := dockerCLI(t, "run", "--rm", "--network", "none", "-v", vol+":/v:ro", HelperImage, "stat", "-c", "%u:%g %a", "/v/t/alice", "/v/t/alice/f")
			t.Logf("without %q: exit %d changed %d errors %q; stat %q", drop, res.ExitCode, rep.Changed, rep.Errors, st)
			ok := res.ExitCode == 0 && rep.Changed == 1 && strings.HasPrefix(st, "20000:20000 700\n")
			if want := drop == ""; ok != want {
				t.Errorf("without %s: success %v, want %v", drop, ok, want)
			}
			if !strings.HasSuffix(st, "1000:100 640") {
				t.Errorf("the file inside changed (childfix isn't recursive): %q", st)
			}
		})
	}
}
