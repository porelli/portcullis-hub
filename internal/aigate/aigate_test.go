package aigate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func vector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// G47 / contract §15.4: the shared vector (the same bytes as core's
// mcp-gate/internal/config/testdata/) decodes strictly and re-encodes
// byte for byte.
func TestVectorRoundTrip(t *testing.T) {
	gate := vector(t, "mcp-gate.json")
	f, err := DecodeFile(gate)
	if err != nil {
		t.Fatalf("mcp-gate.json: %v", err)
	}
	out, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, gate) {
		t.Errorf("mcp-gate.json re-encoded differs:\n%s", out)
	}
	creds := vector(t, "mcp-credentials.json")
	cf, err := DecodeCredFile(creds)
	if err != nil {
		t.Fatalf("mcp-credentials.json: %v", err)
	}
	out, err = cf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, creds) {
		t.Errorf("mcp-credentials.json re-encoded differs:\n%s", out)
	}
}

// The gate's refusals, mirrored (core config_test.go TestStrictDecodeRefuses):
// the Hub never writes a file the gate would refuse.
func TestStrictDecodeRefuses(t *testing.T) {
	gate := string(vector(t, "mcp-gate.json"))
	for name, mut := range map[string][2]string{
		"unknown field":            {`"version": 1,`, `"version": 1, "extra": true,`},
		"case-variant key":         {`"version": 1,`, `"Version": 1,`},
		"duplicate key":            {`"version": 1,`, `"version": 1, "version": 1,`},
		"missing field":            {`"main_domain": "example.com",`, ``},
		"missing resource field":   {`"label": "Gitea",`, ``},
		"null list":                {`"allowed_origins": [],`, `"allowed_origins": null,`},
		"other version":            {`"version": 1,`, `"version": 2,`},
		"issuer not auth.<d>":      {`"issuer": "https://auth.example.com/realms/portcullis"`, `"issuer": "https://evil.example/realms/portcullis"`},
		"forward-auth client":      {"\"portcullis-ai-generic\"\n  ],", "\"portcullis-ai-generic\", \"portcullis-forward-auth\"\n  ],"},
		"client not top-level":     {`"clients": [` + "\n        \"portcullis-ai-claude\",", `"clients": [` + "\n        \"gitea\", \"portcullis-ai-claude\","},
		"companion on a core host": {"    \"example.com\",\n", "    \"example.com\",\n    \"gitea.example.com\",\n"},
		"companion hosts core":     {"\"hosts\": [\n        \"gitea.example.com\"\n      ]", "\"hosts\": [\n        \"gitea.example.com\", \"hub.example.com\"\n      ]"},
		"bad upstream":             {`"upstream": "http://portcullis-mcp-gitea--gitea:8080/mcp"`, `"upstream": "http://169.254.169.254/latest"`},
		"fanout 5":                 {`"fanout": 4,`, `"fanout": 5,`},
		"min_loa 3":                {`"min_loa": 2,` + "\n      \"upstream\": \"http://portcullis-mcp-gitea", `"min_loa": 3,` + "\n      \"upstream\": \"http://portcullis-mcp-gitea"},
		"aggregate min_loa 1":      {`"min_loa": 2,` + "\n      \"upstream\": \"\",\n      \"protocol\": [],\n      \"mode\": \"\",\n      \"identity\": {\n        \"mode\": \"none\",\n        \"header\": \"\",\n        \"format\": \"\",\n        \"basic_user\": \"\",\n        \"secret_ref\": \"\"\n      },\n      \"tools\": {\n        \"writes\": [],\n        \"confirm\": [],\n        \"never\": []\n      },\n      \"aggregate\": false,\n      \"population\": [\n        \"alice\",\n        \"bob\",", `"min_loa": 1,` + "\n      \"upstream\": \"\",\n      \"protocol\": [],\n      \"mode\": \"\",\n      \"identity\": {\n        \"mode\": \"none\",\n        \"header\": \"\",\n        \"format\": \"\",\n        \"basic_user\": \"\",\n        \"secret_ref\": \"\"\n      },\n      \"tools\": {\n        \"writes\": [],\n        \"confirm\": [],\n        \"never\": []\n      },\n      \"aggregate\": false,\n      \"population\": [\n        \"alice\",\n        \"bob\","},
		"bad scope":                {`"scope": "mcp:gitea.gitea",`, `"scope": "mcp:all",`},
		"unsupported protocol":     {"\"2026-07-28\",\n        \"2025-11-25\"", "\"2026-07-28\",\n        \"2025-03-26\""},
		"unsorted population":      {"\"population\": [\n        \"alice\",\n        \"bob\"\n      ],", "\"population\": [\n        \"bob\",\n        \"alice\"\n      ],"},
		"uppercase user":           {"\"population\": [\n        \"alice\",\n        \"bob\"\n      ],", "\"population\": [\n        \"Alice\",\n        \"bob\"\n      ],"},
		"Kelvin sign user":         {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"\u212aim\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"non-ASCII user":           {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"b\u00f6b\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user with @":              {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"b@b\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user with +":              {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"b+b\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user leading .":           {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \".bob\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user leading -":           {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"-bob\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user 65 chars":            {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"expiring not UTC":         {`"bob": "2027-03-31T23:59:59Z"`, `"bob": "2027-03-31T23:59:59+02:00"`},
		"expiring outside pop":     {`"bob": "2027-03-31T23:59:59Z"`, `"zed": "2027-03-31T23:59:59Z"`},
		"people on app_token":      {`"expiring": {` + "\n        \"bob\"", `"people": {}, "expiring": {` + "\n        \"bob\""},
		"identity header cookie":   {`"header": "Authorization",` + "\n        \"format\": \"token {credential}\"", `"header": "Cookie",` + "\n        \"format\": \"token {credential}\""},
		"secret_ref other":         {`"secret_ref": "grafana/grafana"`, `"secret_ref": "gitea/gitea"`},
		"fixed limit changed":      {`"upstream_timeout_s": 120`, `"upstream_timeout_s": 600`},
		"zero limit":               {`"resource_rpm": 120,`, `"resource_rpm": 0,`},
		"origin not https":         {`"allowed_origins": [],`, `"allowed_origins": ["http://claude.ai"],`},
		"trailing data":            {"\n}\n", "\n}\n{}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(gate, mut[0]) {
				t.Fatalf("mutation anchor %q not in the vector", mut[0])
			}
			b := strings.Replace(gate, mut[0], mut[1], 1)
			_, err := DecodeFile([]byte(b))
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
	creds := string(vector(t, "mcp-credentials.json"))
	for name, mut := range map[string][2]string{
		"unknown field":      {`"state": "active",`, `"state": "active", "secret": "x",`},
		"revoking with age":  {`"state": "revoking",` + "\n      \"age\": \"\"", `"state": "revoking",` + "\n      \"age\": \"x\""},
		"active without age": {`"state": "active",` + "\n      \"age\": \"-----BEGIN AGE ENCRYPTED FILE-----\\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBleGFtcGxl\\n-----END AGE ENCRYPTED FILE-----\\n\"", `"state": "active",` + "\n      \"age\": \"\""},
		"bad state":          {`"state": "active",`, `"state": "paused",`},
		"bad id":             {`"id": "7",`, `"id": "7 8",`},
		"unsorted":           {`"user": "carol",`, `"user": "aaron",`},
		"missing field":      {`"minted_at": "2026-11-05T09:30:00Z",`, ``},
	} {
		t.Run("creds/"+name, func(t *testing.T) {
			if !strings.Contains(creds, mut[0]) {
				t.Fatalf("mutation anchor %q not in the vector", mut[0])
			}
			b := strings.Replace(creds, mut[0], mut[1], 1)
			_, err := DecodeCredFile([]byte(b))
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
}

// Encrypt: armored age ciphertext only the recipient's identity opens.
func TestEncryptArmored(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := age.GenerateX25519Identity()
	plain := []byte("s3cr3t")
	ct, err := Encrypt(id.Recipient(), plain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "-----BEGIN AGE ENCRYPTED FILE-----\n") || !strings.HasSuffix(ct, "-----END AGE ENCRYPTED FILE-----\n") {
		t.Fatalf("not armored: %q", ct)
	}
	if strings.Contains(ct, "s3cr3t") {
		t.Fatal("plaintext in the ciphertext")
	}
	open := func(i age.Identity) (string, error) {
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(ct)), i)
		if err != nil {
			return "", err
		}
		b, err := io.ReadAll(r)
		return string(b), err
	}
	if got, err := open(id); err != nil || got != "s3cr3t" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	if _, err := open(other); err == nil {
		t.Fatal("another identity decrypted it")
	}
	if _, err := Encrypt(nil, plain); err == nil {
		t.Fatal("nil recipient accepted")
	}
}

// ParseRecipientFile: exactly one X25519 recipient line (core's age.pub).
func TestParseRecipientFile(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o640); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if r, err := ParseRecipientFile(write("ok", id.Recipient().String()+"\n")); err != nil || r.String() != id.Recipient().String() {
		t.Fatalf("ok: %v %v", r, err)
	}
	for name, s := range map[string]string{
		"empty":    "",
		"garbage":  "age1stale\n",
		"two":      id.Recipient().String() + "\n" + id.Recipient().String() + "\n",
		"identity": id.String() + "\n",
	} {
		if _, err := ParseRecipientFile(write(name, s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseRecipientFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing accepted")
	}
}

func TestNames(t *testing.T) {
	for _, c := range [][2]string{
		{CompanionScope("gitea", "gitea"), "mcp:gitea.gitea"},
		{Alias("gitea", "gitea"), "portcullis-mcp-gitea--gitea"},
		{Router("team-b", "repo"), "portcullis-mcp-team-b--repo"},
		{Upstream("gitea", "gitea", 8080, "/mcp"), "http://portcullis-mcp-gitea--gitea:8080/mcp"},
		{CompanionURL("gitea.example.com", "/mcp"), "https://gitea.example.com/mcp"},
		{Issuer("example.com"), "https://auth.example.com/realms/portcullis"},
		{AggregateURL("example.com"), "https://mcp.example.com/mcp"},
		{AdminURL("example.com"), "https://hub.example.com/mcp"},
		{PeopleURL("example.com"), "https://people.example.com/mcp"},
	} {
		if c[0] != c[1] {
			t.Errorf("got %q, want %q", c[0], c[1])
		}
	}
	// a + b-c and a-b + c differ (C2: the -- separator).
	if Alias("a", "b-c") == Alias("a-b", "c") {
		t.Error("alias ambiguous")
	}
	if AliasFits(strings.Repeat("a", 40), strings.Repeat("b", 7)) {
		t.Error("64-character alias fits")
	}
	if !AliasFits(strings.Repeat("a", 40), strings.Repeat("b", 6)) {
		t.Error("63-character alias doesn't fit")
	}
}

// WriteJSON: atomic, 0640, Go's indented form with a trailing newline.
func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, GateFileName)
	f, err := DecodeFile(vector(t, "mcp-gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(p, f); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !bytes.Equal(b, vector(t, "mcp-gate.json")) {
		t.Error("written bytes differ from the vector")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %o, want 0640", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("temporary files left: %v", ents)
	}
}

// WriteFile / WriteCredFile refuse what the gate would refuse and leave
// the previous file in place.
func TestWriteRefusesInvalid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, GateFileName)
	f, _ := DecodeFile(vector(t, "mcp-gate.json"))
	if err := WriteFile(p, f); err != nil {
		t.Fatal(err)
	}
	bad, _ := DecodeFile(vector(t, "mcp-gate.json"))
	bad.Limits.Fanout = 5
	if err := WriteFile(p, bad); err == nil {
		t.Fatal("invalid file written")
	}
	b, _ := os.ReadFile(p)
	if !bytes.Equal(b, vector(t, "mcp-gate.json")) {
		t.Error("previous file replaced")
	}
	cf, _ := DecodeCredFile(vector(t, "mcp-credentials.json"))
	cf.Credentials[0].State = "paused"
	if err := WriteCredFile(filepath.Join(dir, CredsFileName), cf); err == nil {
		t.Fatal("invalid credentials written")
	}
	if _, err := os.Stat(filepath.Join(dir, CredsFileName)); err == nil {
		t.Error("invalid credentials file exists")
	}
}

func TestAt(t *testing.T) {
	loc := time.FixedZone("x", 7200)
	got := At(time.Date(2027, 3, 31, 23, 59, 59, 999, loc))
	if got.Location() != time.UTC || got.Nanosecond() != 0 || !got.Equal(time.Date(2027, 3, 31, 21, 59, 59, 0, time.UTC)) {
		t.Errorf("At = %v", got)
	}
}
