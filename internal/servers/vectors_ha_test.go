package servers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/jsonstrict"
)

// joinCodeV2Payload is the decoded join code v2 (contract §20.3).
type joinCodeV2Payload struct {
	V            int               `json:"v"`
	Kind         string            `json:"kind"`
	Endpoint     string            `json:"endpoint"`
	Servers      []string          `json:"servers"`
	ServerID     string            `json:"server_id"`
	Role         string            `json:"role"`
	Class        string            `json:"class"`
	Site         string            `json:"site"`
	CASHA256     string            `json:"ca_sha256"`
	ScriptSHA256 string            `json:"script_sha256"`
	AgentSHA256  map[string]string `json:"agent_sha256"`
	MeshIP       string            `json:"mesh_ip"`
	Secret       string            `json:"secret"`
}

type joinCodeV2Vectors struct {
	Valid []struct {
		Code    string            `json:"code"`
		Decoded joinCodeV2Payload `json:"decoded"`
	} `json:"valid"`
	Invalid []struct {
		Name  string `json:"name"`
		Code  string `json:"code"`
		Error string `json:"error"`
	} `json:"invalid"`
}

// The exact errors of contract §20.3 (seven, plus the two sha256 errors of
// the Task 2 fix round) (the f of "field <f> missing" is a
// top-level key).
var joinCodeV2Errors = []string{
	"join code: not a pcj2 code",
	"join code: too long",
	"join code: field ",
	"join code: role must be server or agent",
	"join code: mesh_ip outside 10.215.0.0/24",
	"join code: secret must be 32 bytes",
	"join code: script_sha256 must be 64 hex",
	"join code: ca_sha256 must be 64 hex",
	"join code: agent_sha256 must be 64 hex for amd64 and arm64",
}

// TestJoinCodeV2VectorsShape: joincode_v2_vectors.json (byte-copied to core
// nodeadm/testdata/; the nodeagent's tests read this file, X1) decodes
// strictly; every valid code is pcj2. + base64url (no padding) of its
// decoded payload, ≤ 4 KiB; every contract error has a vector.
func TestJoinCodeV2VectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/joincode_v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs joinCodeV2Vectors
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs.Valid) < 4 || len(vs.Invalid) < 30 {
		t.Fatalf("%d valid, %d invalid vectors", len(vs.Valid), len(vs.Invalid))
	}
	exact := false
	for i, v := range vs.Valid {
		exact = exact || len(v.Code) == 4096
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v.Code, "pcj2."))
		if !strings.HasPrefix(v.Code, "pcj2.") || err != nil || len(v.Code) > 4096 {
			t.Errorf("valid[%d]: not a pcj2 code within 4 KiB", i)
			continue
		}
		var p joinCodeV2Payload
		if err := jsonstrict.Decode(raw, &p); err != nil {
			t.Errorf("valid[%d]: %v", i, err)
			continue
		}
		got, _ := json.Marshal(p)
		want, _ := json.Marshal(v.Decoded)
		if !bytes.Equal(got, want) {
			t.Errorf("valid[%d]: the code decodes to %s, decoded is %s", i, got, want)
		}
		if sec, err := base64.RawURLEncoding.DecodeString(p.Secret); err != nil || len(sec) != 32 {
			t.Errorf("valid[%d]: the secret isn't 32 bytes", i)
		}
	}
	if !exact {
		t.Error("no valid code of exactly 4096 characters (the limit is inclusive)")
	}
	for _, e := range joinCodeV2Errors {
		n := 0
		for _, v := range vs.Invalid {
			if strings.HasPrefix(v.Error, e) {
				n++
			}
		}
		if n == 0 {
			t.Errorf("no invalid vector for %q", e)
		}
	}
	for _, v := range vs.Invalid {
		ok := false
		for _, e := range joinCodeV2Errors {
			ok = ok || v.Error == e || (e == "join code: field " && strings.HasSuffix(v.Error, " missing"))
		}
		if !ok || v.Name == "" {
			t.Errorf("invalid %q: error %q isn't one of the contract's", v.Name, v.Error)
		}
	}
}

type siteRolesWant struct {
	Role     string   `json:"role"`
	Warnings []string `json:"warnings"`
}

type siteRolesVector struct {
	Name    string `json:"name"`
	Cluster []struct {
		ID      string `json:"id"`
		Site    string `json:"site"`
		Role    string `json:"role"`
		Healthy bool   `json:"healthy"`
	} `json:"cluster"`
	New struct {
		Site     string         `json:"site"`
		RTTms    map[string]int `json:"rtt_ms"`
		Override string         `json:"override"`
	} `json:"new"`
	Want      jsonstrict.Nullable[siteRolesWant] `json:"want,omitempty"`
	WantError string                             `json:"want_error,omitempty"`
}

// TestSiteRolesVectorsShape: site_roles_vectors.json (byte-copied to core
// nodeadm/testdata/, contract §20.11) decodes strictly; each case has
// exactly one of want / want_error, and the contract's texts are covered.
func TestSiteRolesVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/site_roles_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []siteRolesVector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 30 {
		t.Fatalf("%d vectors", len(vs))
	}
	texts := map[string]bool{}
	for _, v := range vs {
		if v.Want.Valid == (v.WantError != "") {
			t.Errorf("%s: exactly one of want and want_error", v.Name)
		}
		if v.Want.Valid {
			if v.Want.V.Role != "server" && v.Want.V.Role != "agent" {
				t.Errorf("%s: role %q", v.Name, v.Want.V.Role)
			}
			for _, w := range v.Want.V.Warnings {
				texts[w] = true
			}
		}
		texts[v.WantError] = true
		switch v.New.Override {
		case "", "server", "agent":
		default:
			t.Errorf("%s: override %q", v.Name, v.New.Override)
		}
	}
	for _, want := range []string{
		"an even number of servers doesn't add failure tolerance",
		"Only main can survive on its own: add a tie-breaker at a third location (a small cloud VM or a Pi elsewhere).",
		"too far for one cluster: 101 ms (servers need 100 ms or less)",
		"too far for one cluster: 251 ms (agents need 250 ms or less)",
		"no site can take another server without holding a majority of them: this node joins as an agent.",
	} {
		if !texts[want] {
			t.Errorf("no vector carries %q", want)
		}
	}
	missing := false
	for k := range texts {
		missing = missing || (strings.HasPrefix(k, "no mesh answer from ") && strings.HasSuffix(k, ": the node can't join"))
	}
	if !missing {
		t.Error("no vector for a server missing from the RTT report")
	}
	few := false
	for k := range texts {
		few = few || regexp.MustCompile(`^main holds a majority of the servers: add the next server at [a-z][a-z0-9-]*\.$`).MatchString(k)
	}
	if !few {
		t.Error("no vector for main holding a majority (the fewest-server suggestion)")
	}
	agentsAtCap := 0
	for _, v := range vs {
		servers := 0
		for _, n := range v.Cluster {
			if n.Role == "server" {
				servers++
			}
		}
		if servers >= 5 && v.Want.Valid && v.New.Override == "" {
			agentsAtCap++
			if v.Want.V.Role != "agent" {
				t.Errorf("%s: a sixth server suggested (the cap is 5)", v.Name)
			}
		}
	}
	if agentsAtCap < 2 {
		t.Errorf("%d cases at the 5-server cap, want ≥ 2", agentsAtCap)
	}
}
