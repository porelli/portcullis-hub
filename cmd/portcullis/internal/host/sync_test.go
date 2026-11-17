package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/cmd/portcullis/internal/api"
	"github.com/portcullis/hub/internal/cliapi"
)

// fakeHub answers the host's requests from a script.
type fakeHubClient struct {
	mu      sync.Mutex
	bundles []func() (int, any, error) // GET hosts/bundle answers, in order
	reports []cliapi.Report
	enrol   func(cliapi.EnrolRequest) (*cliapi.Bundle, error)
	signed  []string
	calls   []string
}

func (f *fakeHubClient) Do(_ context.Context, method, path string, body any, out any, extra func(*http.Request, []byte) error) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method+" "+path)
	if extra != nil {
		r, _ := http.NewRequest(method, "https://people.example.org"+path, nil)
		raw, _ := json.Marshal(body)
		if body == nil {
			raw = nil
		}
		if err := extra(r, raw); err != nil {
			return 0, err
		}
		f.signed = append(f.signed, r.Header.Get(cliapi.HeaderHostID))
	}
	switch {
	case strings.HasPrefix(path, "/api/cli/v1/hosts/enrol/challenge"):
		return 200, fill(out, cliapi.EnrolChallenge{Challenge: "Y2hhbGxlbmdl"})
	case path == "/api/cli/v1/hosts/enrol":
		b, err := f.enrol(body.(cliapi.EnrolRequest))
		if err != nil {
			return 403, err
		}
		return 200, fill(out, b)
	case path == "/api/cli/v1/hosts/report":
		f.reports = append(f.reports, body.(cliapi.Report))
		return 204, nil
	case strings.HasPrefix(path, "/api/cli/v1/hosts/bundle"):
		if len(f.bundles) == 0 {
			return 204, nil
		}
		next := f.bundles[0]
		f.bundles = f.bundles[1:]
		code, v, err := next()
		if err != nil {
			return code, err
		}
		if v == nil {
			return code, nil
		}
		raw, _ := json.Marshal(v)
		if err := cliapi.UnmarshalStrict(raw, out); err != nil {
			return code, &api.Error{Code: 1, Msg: "the answer is malformed"}
		}
		return code, nil
	}
	return 404, &api.Error{Code: 1, Msg: "not found", Status: 404}
}

func fill(out, v any) error {
	raw, _ := json.Marshal(v)
	return json.Unmarshal(raw, out)
}

// hostFixture is an enrollable fake host.
type hostFix struct {
	sys    *fakeSys
	signer ssh.Signer
	ca     string
	caFP   string
	hub    *fakeHubClient
	code   *cliapi.EnrolCode
}

func newHostFix(t *testing.T) *hostFix {
	t.Helper()
	sys := newFakeSys(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	sys.files[HostPrivateKeyFile] = pem.EncodeToMemory(blk)
	signer, _ := ssh.NewSignerFromKey(priv)
	sys.files[HostKeyFile] = []byte(cliapi.NormalAuthorizedKey(signer.PublicKey()) + "\n")
	ca, fp := caKey(t)
	s := make([]byte, 32)
	rand.Read(s)
	f := &hostFix{sys: sys, signer: signer, ca: ca, caFP: fp, hub: &fakeHubClient{}}
	f.code = &cliapi.EnrolCode{Domain: "example.org", HostID: "web-1", HostGroups: []string{"all", "web"}, UserCAFP: fp, HostCAFP: "SHA256:host",
		Secret: base64.RawURLEncoding.EncodeToString(s), Expires: applyNow.Add(10 * time.Minute)}
	f.hub.enrol = func(r cliapi.EnrolRequest) (*cliapi.Bundle, error) {
		if r.Secret != f.code.Secret || r.HostKey != cliapi.NormalAuthorizedKey(signer.PublicKey()) {
			return nil, errors.New("bad")
		}
		return f.bundle(), nil
	}
	return f
}

func (f *hostFix) bundle() *cliapi.Bundle {
	return &cliapi.Bundle{Version: 1, HostID: "web-1", Serial: 1, UserCAs: []string{f.ca},
		Accounts: []cliapi.Account{{Name: "alice", Kind: "person", UID: 20001, Principals: []string{"u:alice@web"}, Sudo: true}},
		Locked:   []string{}, Remove: []string{}, RevokedKeys: []string{}}
}

func (f *hostFix) enroll(t *testing.T, service string) error {
	t.Helper()
	return Enroll(context.Background(), f.sys, EnrollOptions{Code: f.code, Ceiling: cliapi.DefaultCeiling(), Service: service, Self: "/usr/local/bin/portcullis",
		Client: f.hub, Now: func() time.Time { return applyNow }})
}

func TestEnrolServiceNone(t *testing.T) {
	f := newHostFix(t)
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.sys.files[SyncUnit]; ok || f.sys.ran("systemctl enable") {
		t.Error("a service was installed")
	}
	cfg, err := LoadAgentConfig(f.sys)
	if err != nil || cfg.HostID != "web-1" || !cfg.ServiceNone || f.sys.modes[AgentFile] != 0o600 {
		t.Errorf("agent config %+v %v", cfg, err)
	}
	if got := string(f.sys.files[PrincipalsFile("alice")]); got != "u:alice@web\n" {
		t.Errorf("principals %q", got)
	}
	if len(f.hub.reports) != 1 || !f.hub.reports[0].Applied || f.hub.signed[0] != "web-1" {
		t.Errorf("reports %+v signed %v", f.hub.reports, f.hub.signed)
	}
	// With systemd: the unit, from a root-owned binary.
	f = newHostFix(t)
	f.sys.dirs["/run/systemd/system"] = true
	if err := f.enroll(t, "auto"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.sys.files[SyncUnit]), `ExecStart="/usr/local/bin/portcullis" host sync`) || !f.sys.ran("systemctl enable --now portcullis-host-sync.service") {
		t.Errorf("unit %s", f.sys.files[SyncUnit])
	}
	// No systemd and no launchd: refused with the unit text, nothing written.
	f = newHostFix(t)
	before := f.sys.snapshot()
	err = f.enroll(t, "auto")
	if err == nil || !strings.Contains(err.Error(), "[Service]") || !reflect.DeepEqual(f.sys.snapshot(), before) {
		t.Errorf("no service manager: %v", err)
	}
}

func TestEnrolFirstCAKeyPinnedByCode(t *testing.T) {
	f := newHostFix(t)
	other, _ := caKey(t)
	f.hub.enrol = func(cliapi.EnrolRequest) (*cliapi.Bundle, error) {
		b := f.bundle()
		b.UserCAs = []string{other}
		return b, nil
	}
	before := f.sys.snapshot()
	if err := f.enroll(t, "none"); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("err %v", err)
	}
	if !reflect.DeepEqual(f.sys.snapshot(), before) {
		t.Error("files written")
	}
}

func TestEnrolFailureRestoresEverything(t *testing.T) {
	f := newHostFix(t)
	before := f.sys.snapshot()
	f.sys.sshdT = errors.New("exit 255")
	if err := f.enroll(t, "none"); err == nil {
		t.Fatal("enrolled despite sshd -t")
	}
	after := f.sys.snapshot()
	for p, v := range before {
		if after[p] != v && p != "/etc/passwd" && p != "/etc/group" {
			t.Errorf("%s changed", p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s left behind", p)
		}
	}
	if f.sys.reloads != 0 {
		t.Error("sshd reloaded")
	}
	if n := len(f.hub.reports); n != 1 || f.hub.reports[0].Applied || f.hub.reports[0].Error == "" {
		t.Errorf("error report %+v", f.hub.reports)
	}
}

func syncOnce(t *testing.T, f *hostFix) error {
	t.Helper()
	return Sync(context.Background(), f.sys, SyncOptions{Client: f.hub, Once: true, Now: func() time.Time { return applyNow.Add(time.Hour) }, Sleep: func(context.Context, time.Duration) {}})
}

func TestSyncKeepsFilesOnBadBundle(t *testing.T) {
	f := newHostFix(t)
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	reloads := f.sys.reloads
	before := f.sys.snapshot()
	big := f.bundle()
	big.Serial = 9
	for i := 0; i < 90000; i++ {
		big.RevokedKeys = append(big.RevokedKeys, "ssh-ed25519 AAAA")
	}
	other := f.bundle()
	other.HostID, other.Serial = "web-2", 9
	for name, ans := range map[string]func() (int, any, error){
		"5xx":   func() (int, any, error) { return 502, nil, &api.Error{Code: 1, Msg: "bad gateway", Status: 502} },
		"cut":   func() (int, any, error) { return 0, nil, &api.Error{Code: 5, Msg: "EOF"} },
		"5 MiB": func() (int, any, error) { return 200, nil, &api.Error{Code: 1, Msg: "the answer is too large"} },
		"unknown": func() (int, any, error) {
			return 200, map[string]any{"version": 1, "host_id": "web-1", "evil": true}, nil
		},
		"other host": func() (int, any, error) { return 200, other, nil },
		"bad keys": func() (int, any, error) {
			b := f.bundle()
			b.Serial = 9
			b.RevokedKeys = []string{"nope"}
			return 200, b, nil
		},
		"kind clash": func() (int, any, error) {
			b := f.bundle()
			b.Serial = 9
			b.Accounts[0].Principals = []string{"s:alice@web"}
			return 200, b, nil
		},
		"oversize big": func() (int, any, error) { return 200, big, nil },
	} {
		f.hub.bundles = []func() (int, any, error){ans}
		_ = syncOnce(t, f)
		after := f.sys.snapshot()
		for _, p := range []string{UserCAFile, PrincipalsFile("alice"), DropInFile, SudoersFile, RevokedKeysFile} {
			if before[p] != after[p] {
				t.Errorf("%s: %s changed", name, p)
			}
		}
		if f.sys.reloads != reloads {
			t.Errorf("%s: sshd reloaded", name)
		}
	}
}

func TestSyncRemovedUninstalls(t *testing.T) {
	f := newHostFix(t)
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	f.hub.bundles = []func() (int, any, error){func() (int, any, error) {
		return 403, nil, &api.Error{Code: 4, Msg: "removed", Status: 403, Server: "removed"}
	}}
	if err := syncOnce(t, f); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{DropInFile, UserCAFile, PrincipalsFile("alice"), SudoersFile, AgentFile, StateFile, CeilingFile, RevokedKeysFile} {
		if _, ok := f.sys.files[p]; ok {
			t.Errorf("%s left", p)
		}
	}
	if !f.sys.ran("usermod -L -e 1 -s /usr/sbin/nologin alice") {
		t.Error("alice not locked")
	}
	if _, ok := f.sys.files["/home/breakglass/.ssh/authorized_keys"]; !ok {
		t.Error("the break-glass key touched")
	}
}

func TestSyncFallsBackToPull(t *testing.T) {
	f := newHostFix(t)
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	var slept []time.Duration
	f.hub.bundles = []func() (int, any, error){
		func() (int, any, error) { return 404, nil, &api.Error{Code: 1, Msg: "not found", Status: 404} },
		func() (int, any, error) { b := f.bundle(); b.Serial = 2; return 200, b, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := Sync(ctx, f.sys, SyncOptions{Client: f.hub, Now: func() time.Time { return applyNow }, Sleep: func(_ context.Context, d time.Duration) {
		slept = append(slept, d)
		if len(slept) >= 2 {
			cancel()
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(slept) < 2 || slept[0] != ErrorBackoff || slept[1] != FallbackPull {
		t.Errorf("slept %v", slept)
	}
	st, _ := LoadState(f.sys)
	if st.Serial != 2 {
		t.Errorf("serial %d", st.Serial)
	}
}

func TestReportNeverLogLines(t *testing.T) {
	f := newHostFix(t)
	f.sys.files["/usr/bin/journalctl"] = []byte("bin")
	f.sys.handler["journalctl"] = func([]string) ([]byte, error) {
		return []byte("2026-11-15T09:00:00+0000 web-1 sshd[1]: Accepted publickey for alice from 192.0.2.7 port 5000 ssh2: ED25519-CERT SHA256:x ID pc:alice:web:0123456789abcdef (serial 1) CA ED25519 SHA256:y\n" +
			"2026-11-15T09:01:00+0000 web-1 sshd[2]: Accepted publickey for breakglass from 192.0.2.8 port 5001 ssh2: ED25519 SHA256:z\n"), nil
	}
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	r := f.hub.reports[len(f.hub.reports)-1]
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "Accepted publickey") || strings.Contains(string(raw), "pc:alice") {
		t.Errorf("a log line in the report: %s", raw)
	}
	if r.Logins.Portcullis != 1 || r.Logins.Breakglass != 1 {
		t.Errorf("counts %+v", r.Logins)
	}
}

func TestBreakglassUsedCounted(t *testing.T) {
	f := newHostFix(t)
	f.sys.files["/usr/bin/journalctl"] = []byte("bin")
	f.sys.handler["journalctl"] = func([]string) ([]byte, error) {
		return []byte("2026-11-15T09:01:00+0000 web-1 sshd[2]: Accepted publickey for breakglass from 192.0.2.8 port 5001 ssh2: ED25519 SHA256:z\n"), nil
	}
	f.enroll(t, "none")
	r := f.hub.reports[len(f.hub.reports)-1]
	found := false
	for _, x := range r.Findings {
		if x.Kind == cliapi.FindingBreakglassUsed && strings.Contains(x.Detail, "192.0.2.8") {
			found = true
		}
	}
	if !found || r.Logins.BreakglassLast.From != "192.0.2.8" {
		t.Errorf("report %+v", r)
	}
}

func TestRemoveDeletesOnlyOwnFiles(t *testing.T) {
	f := newHostFix(t)
	f.sys.files[DropInDir+"/10-site.conf"] = []byte("X11Forwarding no\n")
	before := f.sys.snapshot()
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTrust(context.Background(), f.sys, false, true, false); err != nil {
		t.Fatal(err)
	}
	after := f.sys.snapshot()
	for p, v := range before {
		if after[p] != v && p != "/etc/passwd" && p != "/etc/group" {
			t.Errorf("%s changed by remove", p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok && p != "/etc/passwd" && p != "/etc/group" {
			t.Errorf("%s left by remove", p)
		}
	}
}

func TestStatusErrorShape(t *testing.T) {
	var se StatusError = &api.Error{Status: 403, Server: "removed"}
	if se.HTTPStatus() != 403 || se.Text() != "removed" {
		t.Error("api.Error is a StatusError")
	}
}

func TestSyncHealsDriftWithLastBundle(t *testing.T) {
	f := newHostFix(t)
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	f.sys.files[PrincipalsFile("alice")] = []byte("u:mallory@web\n")
	f.hub.bundles = []func() (int, any, error){func() (int, any, error) { return 204, nil, nil }}
	if err := syncOnce(t, f); err != nil {
		t.Fatal(err)
	}
	if got := string(f.sys.files[PrincipalsFile("alice")]); got != "u:alice@web\n" {
		t.Errorf("not healed: %q", got)
	}
	r := f.hub.reports[len(f.hub.reports)-1]
	found := false
	for _, x := range r.Findings {
		if x.Kind == cliapi.FindingDrift && x.Subject == PrincipalsFile("alice") && x.Detail == "fixed" {
			found = true
		}
	}
	if !found {
		t.Errorf("report %+v", r.Findings)
	}
}

// TestAgentRemovalStopsItselfLast (FR-H3): the sync agent removing the
// host after the Hub said "removed" takes the trust away (CA, principals,
// drop-in, accounts locked, sshd reloaded) BEFORE it stops its own unit:
// systemd's stop kills the agent, so anything after it never happens.
func TestAgentRemovalStopsItselfLast(t *testing.T) {
	f := newHostFix(t)
	f.sys.dirs["/run/systemd/system"] = true
	f.sys.files["/run/systemd/system/.x"] = []byte{}
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.sys.files[UserCAFile]; !ok {
		t.Fatal("enrol wrote no CA")
	}
	f.sys.files[SyncUnit] = SyncUnitBody("/usr/local/bin/portcullis") // the agent runs as this unit
	var atStop []string
	f.sys.handler["systemctl"] = func(args []string) ([]byte, error) {
		cmd := strings.Join(args, " ")
		if strings.Contains(cmd, "portcullis-host-sync.service") && (strings.HasPrefix(cmd, "stop") || strings.Contains(cmd, "--now")) {
			for _, p := range []string{UserCAFile, DropInFile, PrincipalsFile("alice")} {
				if _, ok := f.sys.files[p]; ok {
					atStop = append(atStop, p)
				}
			}
			if !f.sys.ran("usermod -L") {
				atStop = append(atStop, "alice not locked")
			}
		}
		return nil, nil
	}
	if err := RemoveTrust(context.Background(), f.sys, false, true, true); err != nil {
		t.Fatal(err)
	}
	if !f.sys.ran("systemctl stop --no-block portcullis-host-sync.service") {
		t.Errorf("the agent never stopped its own unit: %v", f.sys.runs)
	}
	if len(atStop) != 0 {
		t.Errorf("still in place when the agent stopped itself: %v", atStop)
	}
}

// TestUserCAsPinnedAtEnrol (M2): the first bundle must carry exactly the
// code's user CA, and a later bundle with any other CA is refused (the
// files stay as they were).
func TestUserCAsPinnedAtEnrol(t *testing.T) {
	f := newHostFix(t)
	other, _ := caKey(t)
	f.hub.enrol = func(cliapi.EnrolRequest) (*cliapi.Bundle, error) {
		b := f.bundle()
		b.UserCAs = []string{f.ca, other}
		return b, nil
	}
	if err := f.enroll(t, "none"); err == nil {
		t.Fatal("a first bundle with an extra user CA enrolled")
	}
	if _, ok := f.sys.files[UserCAFile]; ok {
		t.Error("files written")
	}
	f = newHostFix(t)
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	ca := string(f.sys.files[UserCAFile])
	f.hub.bundles = []func() (int, any, error){func() (int, any, error) {
		b := f.bundle()
		b.Serial = 2
		b.UserCAs = []string{f.ca, other}
		return 200, b, nil
	}}
	if err := syncOnce(t, f); err == nil || !strings.Contains(err.Error(), "didn't pin") {
		t.Errorf("a bundle with an unpinned CA: %v", err)
	}
	if string(f.sys.files[UserCAFile]) != ca {
		t.Error("the CA file changed")
	}
}

// L-B6: the report's effective blocks name root and the break-glass
// account apart (they used to share "breakglass", the last one winning).
func TestReportEffectiveRootApart(t *testing.T) {
	f := newHostFix(t)
	if err := f.enroll(t, "none"); err != nil {
		t.Fatal(err)
	}
	r := f.hub.reports[len(f.hub.reports)-1]
	if _, ok := r.Effective["root"]; !ok {
		t.Errorf("no root block: %v", slices.Collect(maps.Keys(r.Effective)))
	}
	if _, ok := r.Effective["breakglass"]; !ok {
		t.Errorf("no breakglass block: %v", slices.Collect(maps.Keys(r.Effective)))
	}
}
