package nodeadm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/jsonstrict"
)

type vectorCase struct {
	Name    string `json:"name"`
	Route   string `json:"route"`
	Client  string `json:"client"`
	Request struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"response"`
}

func loadCases(t *testing.T) []vectorCase {
	t.Helper()
	b, err := os.ReadFile("testdata/nodeadm_api_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []vectorCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v.Cases
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func isNull(b json.RawMessage) bool {
	return len(b) == 0 || bytes.Equal(bytes.TrimSpace(b), []byte("null"))
}

// TestNodeadmClientVectors: an httptest server replays every internal
// route case the Hub's certificate (hub.control) makes; the client sends
// exactly the vector's request, decodes every answer to the same JSON,
// and every refusal is an APIError with the vector's status, kind and
// text. Cases whose request the typed client can't produce (a malformed
// body, another mode) are skipped: the client never sends them.
func TestNodeadmClientVectors(t *testing.T) {
	ran, kinds := 0, map[string]bool{}
	for _, c := range loadCases(t) {
		if c.Client != "hub.control" || !strings.HasPrefix(c.Request.Path, "/v1/") {
			continue
		}
		var call func(cl *Client) (any, error)
		id := ""
		if p := strings.TrimPrefix(c.Request.Path, "/v1/nodes/"); p != c.Request.Path {
			id = strings.SplitN(strings.SplitN(p, "/", 2)[0], "?", 2)[0]
		}
		bodyIsEmptyObject := !isNull(c.Request.Body) && jsonEqual(c.Request.Body, []byte(`{}`))
		switch {
		case c.Route == "POST /v1/codes":
			var r CodeRequest
			if isNull(c.Request.Body) || jsonstrict.Decode(c.Request.Body, &r) != nil {
				continue
			}
			call = func(cl *Client) (any, error) { return cl.IssueCode(context.Background(), r) }
		case c.Route == "GET /v1/cluster":
			call = func(cl *Client) (any, error) { return cl.Cluster(context.Background()) }
		case c.Route == "PUT /v1/nodes/{id}/labels":
			var l Labels
			if isNull(c.Request.Body) || jsonstrict.Decode(c.Request.Body, &l) != nil {
				continue
			}
			call = func(cl *Client) (any, error) { return nil, cl.SetLabels(context.Background(), id, l) }
		case strings.HasSuffix(c.Route, "/cordon"), strings.HasSuffix(c.Route, "/uncordon"), strings.HasSuffix(c.Route, "/drain"):
			if !bodyIsEmptyObject {
				continue
			}
			f := map[string]func(*Client, context.Context, string) error{"cordon": (*Client).Cordon, "uncordon": (*Client).Uncordon, "drain": (*Client).Drain}[c.Route[strings.LastIndex(c.Route, "/")+1:]]
			call = func(cl *Client) (any, error) { return nil, f(cl, context.Background(), id) }
		case strings.HasPrefix(c.Route, "DELETE /v1/nodes/{id}"):
			mode := RemoveMode(strings.TrimPrefix(c.Request.Path[strings.Index(c.Request.Path, "?")+1:], "mode="))
			if !strings.Contains(c.Request.Path, "?mode=") || (mode != Cooperative && mode != Revoke) {
				continue
			}
			call = func(cl *Client) (any, error) { return nil, cl.Remove(context.Background(), id, mode) }
		default:
			t.Errorf("%s: route %s isn't one the client knows", c.Name, c.Route)
			continue
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, _ := io.ReadAll(r.Body)
			if r.Method != c.Request.Method || r.URL.RequestURI() != c.Request.Path {
				t.Errorf("%s: %s %s, want %s %s", c.Name, r.Method, r.URL.RequestURI(), c.Request.Method, c.Request.Path)
			}
			if isNull(c.Request.Body) != (len(got) == 0) || (len(got) > 0 && !jsonEqual(got, c.Request.Body)) {
				t.Errorf("%s: body %s, want %s", c.Name, got, c.Request.Body)
			}
			for k, v := range c.Response.Headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(c.Response.Status)
			if !isNull(c.Response.Body) {
				w.Write(c.Response.Body)
			}
		}))
		got, err := call(&Client{BaseURL: srv.URL, HTTP: srv.Client()})
		srv.Close()
		ran++
		if c.Response.Status/100 == 2 {
			if err != nil {
				t.Errorf("%s: %v", c.Name, err)
				continue
			}
			if ca, ok := got.(CodeAnswer); ok {
				// Its MarshalJSON redacts: the fields themselves.
				got = map[string]string{"code": ca.Code.Reveal(), "expires_at": ca.ExpiresAt}
			}
			if got != nil {
				b, _ := json.Marshal(got)
				if !jsonEqual(b, c.Response.Body) {
					t.Errorf("%s: decoded to %s, want %s", c.Name, b, c.Response.Body)
				}
			}
			continue
		}
		var ae *APIError
		var want struct{ Error, Kind string }
		json.Unmarshal(c.Response.Body, &want)
		if !errors.As(err, &ae) || ae.Status != c.Response.Status || ae.Kind != want.Kind || ae.Text != want.Error {
			t.Errorf("%s: %#v, want %d %q %q", c.Name, err, c.Response.Status, want.Kind, want.Error)
			continue
		}
		kinds[ae.Kind] = true
	}
	if ran < 25 {
		t.Errorf("%d cases ran", ran)
	}
	for _, k := range []string{KindQuorumMinimum, KindReplicaMinimum, KindUnknownNode, KindNotLeader} {
		if !kinds[k] {
			t.Errorf("no case answered kind %s", k)
		}
	}
}

// TestNodeadmClientFenced: once the write gate is closed (the Hub stands
// by), every write is refused before it leaves; the snapshot still reads.
func TestNodeadmClientFenced(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"v":1,"taken_at":"t","nodes":[],"enrolling":[],"pods":[],"quorum":{"etcd":{"voters":1,"healthy":1},"vault":{"voters":1,"healthy":1},"sentinel":{"voters":1,"healthy":1}},"postgres":{"instances":1,"sync_standbys":0,"primary":null},"volumes":[],"errors":[]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	standBy := errors.New("this Hub is standing by: another Hub is the active writer")
	fsutil.SetWriteGate(func() error { return standBy })
	defer fsutil.SetWriteGate(nil)
	cl := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	for name, err := range map[string]error{
		"cordon": cl.Cordon(context.Background(), "n2"), "drain": cl.Drain(context.Background(), "n2"),
		"remove": cl.Remove(context.Background(), "n2", Revoke), "labels": cl.SetLabels(context.Background(), "n2", Labels{Class: "home", Site: "main"}),
	} {
		if !errors.Is(err, standBy) {
			t.Errorf("%s while standing by: %v", name, err)
		}
	}
	if _, err := cl.IssueCode(context.Background(), CodeRequest{}); !errors.Is(err, standBy) {
		t.Errorf("issue while standing by: %v", err)
	}
	if calls != 0 {
		t.Errorf("%d writes left the Hub", calls)
	}
	if _, err := cl.Cluster(context.Background()); err != nil || calls != 1 {
		t.Errorf("the snapshot while standing by: %v (%d calls)", err, calls)
	}
}

// TestCodeAnswerRedacted: a code answer never prints its code.
func TestCodeAnswerRedacted(t *testing.T) {
	a := CodeAnswer{Code: "pcj2.SECRET", ExpiresAt: "2026-11-18T10:15:00Z"}
	js, _ := json.Marshal(a)
	jsc, _ := json.Marshal(map[string]any{"c": a.Code})
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "answer", a, "code", a.Code)
	for _, s := range []string{a.String(), a.GoString(), string(js), string(jsc), logged.String(), fmt.Sprintf("%v %+v %#v %s", a, a, a.Code, a.Code)} {
		if strings.Contains(s, "SECRET") {
			t.Errorf("%q carries the code", s)
		}
	}
}
