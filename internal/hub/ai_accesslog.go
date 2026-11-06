package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
)

// The gate's access log (contract §15.8), a person's AI connections and
// Disconnect (§5.1 GET /api/me/ai, DELETE /api/me/ai/connections/{client};
// §8 "Disconnecting"; plan 4 Task 13b). The HTTP routes are Task 21's
// (httpapi/people.go, people listener only).

// AccessLogName is the gate's access log in HUB_MCP_GATE_DATA_DIR.
const AccessLogName = "access.jsonl"

// accessLogTail is how much of the end of the log is read (§15.8).
const accessLogTail = 4 << 20

// myAILines is how many of the caller's own lines MyAI returns.
const myAILines = 50

// AccessLine is one access-log line (§15.8; core's
// mcp-gate/internal/accesslog wire form, keys in its order).
type AccessLine struct {
	Time           time.Time `json:"time"`
	User           string    `json:"user"`
	Client         string    `json:"client"`
	Resource       string    `json:"resource"`
	Instance       string    `json:"instance"`
	Companion      string    `json:"companion"`
	Via            string    `json:"via"`
	Method         string    `json:"method"`
	Tool           string    `json:"tool"`
	ArgsSHA256     string    `json:"args_sha256"`
	Decision       string    `json:"decision"`
	UpstreamStatus int       `json:"upstream_status"`
	DurationMS     int64     `json:"duration_ms"`
	ConfirmationID string    `json:"confirmation_id,omitempty"`
}

// accessWire is the line as the gate writes it (time as RFC 3339 text).
type accessWire struct {
	Time           string `json:"time"`
	User           string `json:"user"`
	Client         string `json:"client"`
	Resource       string `json:"resource"`
	Instance       string `json:"instance"`
	Companion      string `json:"companion"`
	Via            string `json:"via"`
	Method         string `json:"method"`
	Tool           string `json:"tool"`
	ArgsSHA256     string `json:"args_sha256"`
	Decision       string `json:"decision"`
	UpstreamStatus int    `json:"upstream_status"`
	DurationMS     int64  `json:"duration_ms"`
	ConfirmationID string `json:"confirmation_id,omitempty"`
}

// parseAccessLine decodes one line as core's ParseLine does: strict (no
// unknown key, one document), time RFC 3339.
func parseAccessLine(b []byte) (AccessLine, error) {
	var w accessWire
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return AccessLine{}, err
	}
	if dec.More() {
		return AccessLine{}, errors.New("trailing data")
	}
	t, err := time.Parse(time.RFC3339, w.Time)
	if err != nil {
		return AccessLine{}, err
	}
	return AccessLine{Time: t.UTC(), User: w.User, Client: w.Client, Resource: w.Resource, Instance: w.Instance,
		Companion: w.Companion, Via: w.Via, Method: w.Method, Tool: w.Tool, ArgsSHA256: w.ArgsSHA256,
		Decision: w.Decision, UpstreamStatus: w.UpstreamStatus, DurationMS: w.DurationMS, ConfirmationID: w.ConfirmationID}, nil
}

// errAccessLog is the generic answer when the log can't be read.
var errAccessLog = statusErr(http.StatusServiceUnavailable, "AI activity can't be read right now")

// AccessLog returns up to n lines of HUB_MCP_GATE_DATA_DIR/access.jsonl
// that filter accepts (nil = all), newest first. Only the last 4 MiB are
// read: a partial first line there and a torn last line (no newline yet:
// the gate is mid-write) are skipped, and so is any line that doesn't
// decode (counted in the log). No log yet = none; no data dir or an
// unreadable file = 503.
func (h *Hub) AccessLog(filter func(AccessLine) bool, n int) ([]AccessLine, error) {
	out := []AccessLine{}
	if n <= 0 {
		return out, nil
	}
	if h.cfg.MCPGateDataDir == "" {
		return nil, errAccessLog
	}
	f, err := os.Open(filepath.Join(h.cfg.MCPGateDataDir, AccessLogName))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		log.Printf("ai: the access log: %v", err)
		return nil, errAccessLog
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		log.Printf("ai: the access log: %v", err)
		return nil, errAccessLog
	}
	off := int64(0)
	if st.Size() > accessLogTail {
		off = st.Size() - accessLogTail
	}
	buf, err := io.ReadAll(io.NewSectionReader(f, off, st.Size()-off))
	if err != nil {
		log.Printf("ai: the access log: %v", err)
		return nil, errAccessLog
	}
	if off > 0 {
		// The first line is a fragment unless the cut fell right after a
		// newline.
		var prev [1]byte
		if _, err := f.ReadAt(prev[:], off-1); err != nil || prev[0] != '\n' {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				return out, nil
			}
			buf = buf[i+1:]
		}
	}
	// A torn last line: everything after the last newline.
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[:i+1]
	} else {
		buf = nil
	}
	lines := bytes.Split(bytes.TrimSuffix(buf, []byte("\n")), []byte("\n"))
	bad := 0
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if len(bytes.TrimSpace(lines[i])) == 0 {
			continue
		}
		l, err := parseAccessLine(lines[i])
		if err != nil {
			bad++
			continue
		}
		if filter == nil || filter(l) {
			out = append(out, l)
		}
	}
	if bad > 0 {
		log.Printf("ai: the access log: %d line(s) that don't decode skipped", bad)
	}
	return out, nil
}

// ── connections ───────────────────────────────────────────

// AIConnector is the Keycloak side of a person's AI connections
// (keycloak.Client). The AIKeycloak wired with SetAIKeycloak provides it
// when it implements these (main's does); else MyAI / DisconnectAI
// answer 503 and the reconcile removes no connection.
type AIConnector interface {
	AIConnections(ctx context.Context, username string, clients []string) ([]keycloak.AIConnection, error)
	RevokeAIConnection(ctx context.Context, username, clientID string) error
}

func (h *Hub) aiConnector() AIConnector {
	c, _ := h.aiKeycloak().(AIConnector)
	return c
}

// revokeConnection deletes username's consent and offline sessions for
// client; a client Keycloak doesn't have (or that isn't an AI client
// there) holds no connection.
func revokeConnection(ctx context.Context, kc AIConnector, username, client string) error {
	err := kc.RevokeAIConnection(ctx, username, client)
	if errors.Is(err, keycloak.ErrClientNotFound) || errors.Is(err, keycloak.ErrNotAIClient) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("client %s: %w", client, err)
	}
	return nil
}

// MyAIConnection is one of the caller's AI connections (§5.1).
type MyAIConnection struct {
	Client      string     `json:"client"`
	Label       string     `json:"label"`
	ConsentedAt *time.Time `json:"consented_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// MyAIView is GET /api/me/ai: the caller's connections and their own last
// 50 access-log lines, newest first.
type MyAIView struct {
	Connections []MyAIConnection `json:"connections"`
	Activity    []AccessLine     `json:"activity"`
}

// aiClientLabel is the Hub's name for an AI client.
func (h *Hub) aiClientLabel(id string) string {
	switch id {
	case keycloak.AIClientIDs.Claude:
		return "Claude"
	case keycloak.AIClientIDs.ClaudeCode:
		return "Claude Code"
	case keycloak.AIClientIDs.Generic:
		return "Other MCP clients"
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := range h.instances {
		t := &h.instances[i]
		for _, c := range t.Manifest.Clients {
			if c.AIClient && t.InstanceClientID(c.ClientID) == id {
				return instanceName(t)
			}
		}
	}
	return id
}

// myUser is the caller's username as the people listener's identity
// gives it (X-Forwarded-User), lowercased; never an email.
func myUser(user string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(user))
	if !aigate.ValidUsername(u) {
		return "", statusErr(http.StatusUnauthorized, "no signed-in user")
	}
	return u, nil
}

// MyAI is the caller's AI connections (every AI client they have a
// consent or an offline session for) and their own last 50 access-log
// lines. Only the caller's data; 503 when Keycloak or the log can't be
// read.
func (h *Hub) MyAI(ctx context.Context, user string) (*MyAIView, error) {
	u, err := myUser(user)
	if err != nil {
		return nil, err
	}
	kc := h.aiConnector()
	if kc == nil {
		return nil, statusErr(http.StatusServiceUnavailable, "AI connections can't be read right now")
	}
	conns, err := kc.AIConnections(ctx, u, h.aiClientIDs())
	if err != nil {
		log.Printf("ai: %s's AI connections: %v", u, err)
		return nil, statusErr(http.StatusServiceUnavailable, "AI connections can't be read right now")
	}
	activity, err := h.AccessLog(func(l AccessLine) bool { return l.User == u }, myAILines)
	if err != nil {
		return nil, err
	}
	v := &MyAIView{Connections: []MyAIConnection{}, Activity: activity}
	for _, c := range conns {
		v.Connections = append(v.Connections, MyAIConnection{Client: c.Client, Label: h.aiClientLabel(c.Client),
			ConsentedAt: c.Consented, LastUsedAt: c.LastUsed, ExpiresAt: c.Expires})
	}
	slices.SortFunc(v.Connections, func(a, b MyAIConnection) int { return strings.Compare(a.Client, b.Client) })
	return v, nil
}

// DisconnectAI revokes user's consent and offline sessions for the AI
// client client (§8): only one of the Hub's AI client ids (else 404);
// nothing there is fine. Audited ai.connection.revoke (target the user,
// detail the client). The whole call counts toward the people
// listener's per-caller refusal limit (§5.1 common rules, 429).
func (h *Hub) DisconnectAI(ctx context.Context, user, client string, actor directory.Actor) (err error) {
	u, err := myUser(user)
	if err != nil {
		return err
	}
	if !h.entryLimit.reserve(u, h.entryClock()) {
		return errEntryLimited
	}
	defer func() { h.entryLimit.release(u, h.entryClock(), isRefusal(err)) }()
	return h.disconnectAI(ctx, u, client, actor)
}

func (h *Hub) disconnectAI(ctx context.Context, u, client string, actor directory.Actor) error {
	if !slices.Contains(h.aiClientIDs(), client) {
		return statusErr(http.StatusNotFound, "no such AI client")
	}
	if err := actor.Check(); err != nil {
		return statusErr(http.StatusForbidden, "%v", err)
	}
	kc := h.aiConnector()
	if kc == nil {
		err := statusErr(http.StatusServiceUnavailable, "AI connections can't be changed right now")
		h.auditAI(actor, "ai.connection.revoke", u, client, err)
		return err
	}
	if err := revokeConnection(ctx, kc, u, client); err != nil {
		log.Printf("ai: disconnecting %s from %s: %v", u, client, err)
		h.auditAI(actor, "ai.connection.revoke", u, client, err)
		return statusErr(http.StatusServiceUnavailable, "AI connections can't be changed right now")
	}
	h.auditAI(actor, "ai.connection.revoke", u, client, nil)
	return nil
}
