// Package mcpsdk is the one place the Hub touches the official MCP Go SDK
// (github.com/modelcontextprotocol/go-sdk, pinned v1.8.0, the gate's
// version; preflight G18) and its JSON Schema library, so a later SDK
// version has one place to change. The Hub's MCP (contract §15.10) is a
// stateless Streamable HTTP server: Handler builds it.
package mcpsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type (
	Server              = mcp.Server
	Tool                = mcp.Tool
	ToolAnnotations     = mcp.ToolAnnotations
	ToolHandler         = mcp.ToolHandler
	CallToolRequest     = mcp.CallToolRequest
	CallToolResult      = mcp.CallToolResult
	Content             = mcp.Content
	TextContent         = mcp.TextContent
	ElicitParams        = mcp.ElicitParams
	ElicitResult        = mcp.ElicitResult
	InputRequestMap     = mcp.InputRequestMap
	Resource            = mcp.Resource
	ResourceTemplate    = mcp.ResourceTemplate
	ResourceHandler     = mcp.ResourceHandler
	ReadResourceRequest = mcp.ReadResourceRequest
	ReadResourceResult  = mcp.ReadResourceResult
	ResourceContents    = mcp.ResourceContents
	Prompt              = mcp.Prompt
	PromptArgument      = mcp.PromptArgument
	PromptHandler       = mcp.PromptHandler
	GetPromptRequest    = mcp.GetPromptRequest
	GetPromptResult     = mcp.GetPromptResult
	PromptMessage       = mcp.PromptMessage
	ListToolsResult     = mcp.ListToolsResult
	Middleware          = mcp.Middleware
	MethodHandler       = mcp.MethodHandler
	Request             = mcp.Request
	Result              = mcp.Result
)

// Protocol versions (contract §15.3): exactly these, newest first.
const (
	ProtocolStateless = "2026-07-28" // sessionless: URL elicitations in an InputRequiredResult
	Protocol20251125  = "2025-11-25"
	Protocol20250618  = "2025-06-18"
)

// SupportedProtocols are the versions the Hub's MCP accepts.
var SupportedProtocols = []string{ProtocolStateless, Protocol20251125, Protocol20250618}

// Codes of the JSON-RPC errors the Hub answers itself.
const (
	CodeUnsupportedProtocolVersion = mcp.CodeUnsupportedProtocolVersion
	CodeHeaderMismatch             = mcp.CodeHeaderMismatch // -32020
)

// MethodListTools is the method ListToolsFilter acts on.
const MethodListTools = "tools/list"

// ErrResourceNotFound is a resources/read of an unknown URI.
var ErrResourceNotFound = mcp.ResourceNotFoundError

// NewServer is a server with tools, resources and prompts, none of which
// announces list changes (a stateless server can't send them).
func NewServer(name, title string) *Server {
	s := mcp.NewServer(&mcp.Implementation{Name: name, Title: title, Version: "1"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools:     &mcp.ToolCapabilities{},
			Resources: &mcp.ResourceCapabilities{},
			Prompts:   &mcp.PromptCapabilities{},
		},
		SupportedProtocolVersions: SupportedProtocols, // G18
	})
	return s
}

// MaxRequestBytes bounds a request body (§15.9: the gate's own cap).
const MaxRequestBytes = 8 << 20

// Handler is the stateless Streamable HTTP handler of server(r) (contract
// §15.10: no sessions, no GET stream). Before the SDK runs, the protocol
// version is checked as §15.3 says — the MCP-Protocol-Version header, or
// an initialize body's protocolVersion, must be one of
// SupportedProtocols, else 400 "unsupported protocol version" (the SDK
// alone lets newer versions through and negotiates an older initialize
// down) — and the SDK then checks Mcp-Method / Mcp-Name and _meta
// against the body (-32020).
func Handler(server func(*http.Request) *Server) http.Handler {
	h := mcp.NewStreamableHTTPHandler(server, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		DisableLocalhostProtection: true, // reached only through the gate, with the MCP secret
		MaxRequestBodyBytes:        MaxRequestBytes,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
			if err != nil {
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			if !protocolOK(r.Header, body) {
				writeRPCError(w, http.StatusBadRequest, CodeUnsupportedProtocolVersion, "unsupported protocol version")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.ServeHTTP(w, r)
	})
}

// protocolOK: the header (at most one), when present, is supported; an
// initialize request's protocolVersion is supported and, with a header,
// equal to it; any other request without the header is refused.
func protocolOK(h http.Header, body []byte) bool {
	vals := h.Values("Mcp-Protocol-Version")
	if len(vals) > 1 || (len(vals) == 1 && !slices.Contains(SupportedProtocols, vals[0])) {
		return false
	}
	msg, err := jsonrpc.DecodeMessage(body)
	if err != nil {
		return true // not one message: the SDK answers it
	}
	req, ok := msg.(*jsonrpc.Request)
	if !ok {
		return true
	}
	if req.Method != "initialize" {
		// Every request but initialize names its version in the header
		// (§15.3; 2025-06-18 and later): none = unsupported.
		return len(vals) == 1
	}
	var p mcp.InitializeParams
	if json.Unmarshal(req.Params, &p) != nil || !slices.Contains(SupportedProtocols, p.ProtocolVersion) {
		return false
	}
	return len(vals) == 0 || vals[0] == p.ProtocolVersion
}

func writeRPCError(w http.ResponseWriter, status int, code int64, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": code, "message": msg}})
	w.Write(b)
}

// Schema is the JSON Schema of an argument struct type (structs get
// additionalProperties: false; fields without omitempty are required),
// its top-level property names, and a validator for decoded arguments.
func Schema(t reflect.Type) (raw json.RawMessage, props []string, validate func(any) error, err error) {
	// json.RawMessage is any JSON value (a setting's value), not the
	// byte slice it is in Go.
	s, err := jsonschema.ForType(t, &jsonschema.ForOptions{TypeSchemas: map[reflect.Type]*jsonschema.Schema{
		reflect.TypeFor[json.RawMessage](): {},
	}})
	if err != nil {
		return nil, nil, nil, err
	}
	if s.Type != "object" {
		return nil, nil, nil, errors.New("tool arguments must be an object")
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, err = json.Marshal(s)
	if err != nil {
		return nil, nil, nil, err
	}
	for k := range s.Properties {
		props = append(props, k)
	}
	slices.Sort(props)
	return raw, props, rs.Validate, nil
}

// Call is what a tool handler needs from a tools/call request: its raw
// arguments, the negotiated protocol version, whether the client
// declared URL-mode elicitation, and the answer the client gave to an
// earlier input request with id key ("" = none; "accept", "decline",
// "cancel").
type Call struct {
	Arguments  json.RawMessage
	Protocol   string
	URLElicit  bool
	InputReply func(key string) string
}

// CallOf reads req.
func CallOf(req *CallToolRequest) Call {
	c := Call{InputReply: func(string) string { return "" }}
	if req == nil || req.Params == nil {
		return c
	}
	c.Arguments = req.Params.Arguments
	c.Protocol = req.ProtocolVersion()
	if caps := req.ClientCapabilities(); caps != nil && caps.Elicitation != nil && caps.Elicitation.URL != nil {
		c.URLElicit = true
	}
	responses := req.Params.InputResponses
	c.InputReply = func(key string) string {
		if r, ok := responses[key].(*mcp.ElicitResult); ok && r != nil {
			return r.Action
		}
		return ""
	}
	return c
}

// TextResult is a tool result with one text content.
func TextResult(text string, isError bool) *CallToolResult {
	return &CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}, IsError: isError}
}

// TextOf is the text of r's first content ("" when it has none).
func TextOf(r *CallToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	if t, ok := r.Content[0].(*mcp.TextContent); ok {
		return t.Text
	}
	return ""
}

// URLInputRequired is a 2026-07-28 tools/call result of resultType
// "input_required" (SEP-2322) asking for one URL-mode elicitation (never
// form mode) under key. The SDK keeps the result type unexported, so it
// is built through the SDK's own decoder (as the gate does).
func URLInputRequired(key, message, url, elicitationID string) (*CallToolResult, error) {
	reqs := mcp.InputRequestMap{key: &mcp.ElicitParams{Mode: "url", Message: message, URL: url, ElicitationID: elicitationID}}
	b, err := json.Marshal(struct {
		ResultType    string              `json:"resultType"`
		InputRequests mcp.InputRequestMap `json:"inputRequests"`
	}{"input_required", reqs})
	if err != nil {
		return nil, err
	}
	var r CallToolResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if !r.NeedsInput() || len(r.InputRequests) != 1 {
		return nil, errors.New("input_required result did not round-trip")
	}
	return &r, nil
}

// TextResource is a resources/read answer of one text.
func TextResource(uri, mime, text string) *ReadResourceResult {
	return &ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: mime, Text: text}}}
}

// UserPrompt is a prompts/get answer of one user message.
func UserPrompt(description, text string) *GetPromptResult {
	return &GetPromptResult{Description: description, Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}
}

// FilterTools is receiving middleware that drops, from every tools/list
// answer, the tools keep(ctx) refuses (keep is built once per request),
// and marks the list private to the person (it depends on who asks).
func FilterTools(keep func(ctx context.Context) func(name string) bool) Middleware {
	return func(next MethodHandler) MethodHandler {
		return func(ctx context.Context, method string, req Request) (Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != MethodListTools {
				return res, err
			}
			lr, ok := res.(*mcp.ListToolsResult)
			if !ok || lr == nil {
				return res, err
			}
			k := keep(ctx)
			out := make([]*mcp.Tool, 0, len(lr.Tools))
			for _, t := range lr.Tools {
				if k(t.Name) {
					out = append(out, t)
				}
			}
			lr.Tools = out
			lr.CacheScope = "private"
			return lr, nil
		}
	}
}

// Codes of the JSON-RPC errors AdminOnly answers.
const (
	codeRefused     = jsonrpc.CodeInvalidRequest
	codeUnavailable = jsonrpc.CodeInternalError
)

// AdminOnly is receiving middleware for the admin server (§15.10: admins
// only): every method but initialize, ping and notifications/* asks
// admin(ctx). An error is a JSON-RPC error with unavailable as its text;
// a non-admin gets empty lists from the list methods, the JSON-RPC error
// "admins only" from resources/read, prompts/get and anything else, and
// reaches tools/call (the tool answers isError "admins only" and audits
// the refusal).
func AdminOnly(admin func(ctx context.Context) (bool, error), unavailable string) Middleware {
	return func(next MethodHandler) MethodHandler {
		return func(ctx context.Context, method string, req Request) (Result, error) {
			if method == "initialize" || method == "ping" || strings.HasPrefix(method, "notifications/") {
				return next(ctx, method, req)
			}
			ok, err := admin(ctx)
			if err != nil {
				return nil, &jsonrpc.Error{Code: codeUnavailable, Message: unavailable}
			}
			if ok {
				return next(ctx, method, req)
			}
			switch method {
			case "tools/call":
				return next(ctx, method, req)
			case MethodListTools:
				return &mcp.ListToolsResult{Tools: []*mcp.Tool{}}, nil
			case "resources/list":
				return &mcp.ListResourcesResult{Resources: []*mcp.Resource{}}, nil
			case "resources/templates/list":
				return &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{}}, nil
			case "prompts/list":
				return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{}}, nil
			}
			return nil, &jsonrpc.Error{Code: codeRefused, Message: "admins only"}
		}
	}
}

// InternalError is the JSON-RPC error of a resource or prompt handler
// that failed unexpectedly (a recovered panic).
func InternalError() error { return &jsonrpc.Error{Code: codeUnavailable, Message: "internal error"} }
