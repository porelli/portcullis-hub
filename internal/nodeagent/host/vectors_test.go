package host

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The nodeadm API vectors (core's nodeadm_api_vectors.json, byte-copied
// to the Hub's internal/nodeadm/testdata) fix the enrol proof, the signed
// join request's canonical bytes and the K10 token form.
func readNodeadmVectors(t *testing.T) map[string]json.RawMessage {
	b, err := os.ReadFile("../../nodeadm/testdata/nodeadm_api_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestProofVectors(t *testing.T) {
	var vs []struct {
		Name       string `json:"name"`
		Secret     string `json:"secret"`
		Nonce      string `json:"nonce"`
		ServerID   string `json:"server_id"`
		SPKISHA256 string `json:"spki_sha256"`
		WantKey    string `json:"want_key_sha256"`
		WantProof  string `json:"want_proof"`
	}
	if err := json.Unmarshal(readNodeadmVectors(t)["proof"], &vs); err != nil || len(vs) == 0 {
		t.Fatal(err)
	}
	for _, v := range vs {
		sec, _ := base64.RawURLEncoding.DecodeString(v.Secret)
		nonce, _ := base64.RawURLEncoding.DecodeString(v.Nonce)
		spkiSum, _ := hex.DecodeString(v.SPKISHA256)
		got := proofFromSPKISum(sec, nonce, v.ServerID, spkiSum)
		if base64.RawURLEncoding.EncodeToString(got) != v.WantProof {
			t.Errorf("%s: proof %s", v.Name, base64.RawURLEncoding.EncodeToString(got))
		}
	}
}

func TestSignedRequestVectors(t *testing.T) {
	var vs []struct {
		Name          string `json:"name"`
		ServerID      string `json:"server_id"`
		Method        string `json:"method"`
		Path          string `json:"path"`
		Time          string `json:"time"`
		Nonce         string `json:"nonce"`
		Body          string `json:"body"`
		WantCanonical string `json:"want_canonical"`
	}
	if err := json.Unmarshal(readNodeadmVectors(t)["signed_request"], &vs); err != nil || len(vs) == 0 {
		t.Fatal(err)
	}
	for _, v := range vs {
		if got := string(CanonicalBytes(v.ServerID, v.Method, v.Path, v.Time, v.Nonce, []byte(v.Body))); got != v.WantCanonical {
			t.Errorf("%s: %s", v.Name, got)
		}
	}
}

func TestK10TokenVectors(t *testing.T) {
	var vs []struct {
		Token string `json:"token"`
		OK    bool   `json:"ok"`
	}
	if err := json.Unmarshal(readNodeadmVectors(t)["join_tokens"], &vs); err != nil || len(vs) == 0 {
		t.Fatal(err)
	}
	for _, v := range vs {
		if K10Re.MatchString(v.Token) != v.OK {
			t.Errorf("%q: %v", v.Token, !v.OK)
		}
	}
}

// TestJoinCodeVectors: the join reads every code of
// joincode_v2_vectors.json (the servers package's, ruling X1: no second
// copy) as the vectors say, the exact error text included.
func TestJoinCodeVectors(t *testing.T) {
	b, err := os.ReadFile("../../servers/testdata/joincode_v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Valid []struct {
			Code    string         `json:"code"`
			Decoded map[string]any `json:"decoded"`
		} `json:"valid"`
		Invalid []struct {
			Name  string `json:"name"`
			Code  string `json:"code"`
			Error string `json:"error"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(b, &d); err != nil || len(d.Valid) == 0 || len(d.Invalid) == 0 {
		t.Fatal(err)
	}
	for _, v := range d.Valid {
		c, err := readCode(strings.NewReader(v.Code + "\n"))
		if err != nil || c.ServerID != v.Decoded["server_id"] || c.MeshIP != v.Decoded["mesh_ip"] {
			t.Errorf("valid code: %v", err)
		}
	}
	for _, v := range d.Invalid {
		_, err := readCode(strings.NewReader(v.Code))
		if err == nil || err.Error() != v.Error {
			t.Errorf("%s: %v, want %q", v.Name, err, v.Error)
		}
	}
}
