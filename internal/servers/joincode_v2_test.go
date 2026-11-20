package servers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/jsonstrict"
)

// TestJoinCodeV2Vectors: every valid code decodes to its decoded payload
// (and EncodeV2 gives the code back, byte for byte); every invalid one
// answers its exact error.
func TestJoinCodeV2Vectors(t *testing.T) {
	b, err := os.ReadFile("testdata/joincode_v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs joinCodeV2Vectors
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	for i, v := range vs.Valid {
		c, err := DecodeJoinCodeV2(v.Code)
		if err != nil {
			t.Errorf("valid[%d]: %v", i, err)
			continue
		}
		d := v.Decoded
		want := JoinCodeV2{V: d.V, Kind: d.Kind, Endpoint: d.Endpoint, Servers: d.Servers, ServerID: d.ServerID, Role: d.Role, Class: d.Class,
			Site: d.Site, CASHA256: d.CASHA256, ScriptSHA256: d.ScriptSHA256, AgentSHA256: AgentSHA256{d.AgentSHA256["amd64"], d.AgentSHA256["arm64"]},
			MeshIP: d.MeshIP, Secret: d.Secret}
		if !reflect.DeepEqual(joinCodeV2Wire(c), joinCodeV2Wire(want)) {
			t.Errorf("valid[%d]: decoded %+v, want %+v", i, joinCodeV2Wire(c), joinCodeV2Wire(want))
		}
		if got := c.EncodeV2(); got != v.Code {
			t.Errorf("valid[%d]: EncodeV2 doesn't give the code back", i)
		}
	}
	for _, v := range vs.Invalid {
		_, err := DecodeJoinCodeV2(v.Code)
		if err == nil || err.Error() != v.Error {
			t.Errorf("%s: %v, want %q", v.Name, err, v.Error)
		}
		if err != nil && len(v.Code) > 20 && strings.Contains(err.Error(), v.Code[5:20]) {
			t.Errorf("%s: the error carries the code", v.Name)
		}
	}
}

// TestJoinCodeV2NeverPrintsSecret: %v, %+v, %#v, %s and JSON of a code
// carry no form of its secret (base64url, base64, hex).
func TestJoinCodeV2NeverPrintsSecret(t *testing.T) {
	b, _ := os.ReadFile("testdata/joincode_v2_vectors.json")
	var vs joinCodeV2Vectors
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	c, err := DecodeJoinCodeV2(vs.Valid[0].Code)
	if err != nil {
		t.Fatal(err)
	}
	raw := c.SecretBytes()
	forms := []string{c.Secret, base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw), hex.EncodeToString(raw)}
	js, _ := json.Marshal(c)
	jsp, _ := json.Marshal(&c)
	wrapped, _ := json.Marshal(map[string]any{"code": c})
	outs := []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%s", c), fmt.Sprint(&c), string(js), string(jsp), string(wrapped)}
	for _, o := range outs {
		for _, f := range forms {
			if strings.Contains(o, f) {
				t.Errorf("%q carries the secret", o)
			}
		}
		if !strings.Contains(o, "n4") {
			t.Errorf("%q lost the server id", o)
		}
	}
}
