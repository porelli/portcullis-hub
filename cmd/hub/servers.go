package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/servers"
)

// `hub servers …` (contract §20.1 "The CLI twins"; pre-flight P19): thin
// clients of the running Hub over the host control socket, run by
// `./portcullis node …` with `kubectl exec -i`. The running Hub does the
// work (its ops, audit — actor cli — and Lease apply once); this process
// holds no state. A request body comes on stdin, never argv; the join
// code is printed on stdout only, everything else on stderr.

const serversUsage = `usage: hub servers add-cluster-node   < {"id", "name"?, "role"?, "class"?, "site"?, "ingress"?, "storage"?}   (the code on stdout)
       hub servers list
       hub servers remove <id>          < {"confirm": "<id>"}
       hub servers revoke <id>          < {"confirm": "<id>"}
       hub servers op <id> [<op_id>]`

// serversTimeout bounds one subcommand's call: a revoke may wait for
// nodeadm's rotations (up to 15 min, §20.2). A variable: tests.
var serversTimeout = func(cmd string) time.Duration {
	if cmd == "revoke" {
		return 20 * time.Minute
	}
	return 2 * time.Minute
}

// serversMain runs `hub servers <args>` against the socket at sock: 0
// done, 1 the Hub refused (a 4xx; the text on stderr), 2 usage or a bad
// body, 3 not answered — the Hub isn't running, its answer was cut or
// timed out, or a 5xx (standing by, nodeadm unreachable): nothing is
// known to have been refused, and `./portcullis node revoke` asks for the
// outcome instead (Task 30 fix round 1).
const serversUnanswered = 3

func serversMain(args []string, stdin io.Reader, stdout, stderr io.Writer, sock string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, serversUsage)
		return 2
	}
	readBody := func() ([]byte, bool) {
		b, err := io.ReadAll(io.LimitReader(stdin, 8<<10+1))
		var obj map[string]json.RawMessage
		if err != nil || len(b) > 8<<10 || json.Unmarshal(b, &obj) != nil || obj == nil {
			fmt.Fprintln(stderr, "hub servers "+args[0]+": the body on stdin must be one JSON object")
			return nil, false
		}
		return b, true
	}
	var method, path string
	var body []byte
	switch {
	case args[0] == "add-cluster-node" && len(args) == 1:
		b, ok := readBody()
		if !ok {
			return 2
		}
		method, path, body = http.MethodPost, "/host/servers/cluster-node", b
	case args[0] == "list" && len(args) == 1:
		method, path = http.MethodGet, "/host/servers"
	case (args[0] == "remove" || args[0] == "revoke") && len(args) == 2:
		if servers.ValidID(args[1]) != nil {
			fmt.Fprintln(stderr, "hub servers "+args[0]+": invalid server id")
			return 2
		}
		b, ok := readBody()
		if !ok {
			return 2
		}
		method, path, body = http.MethodPost, "/host/servers/"+args[1]+"/"+args[0], b
	case args[0] == "op" && (len(args) == 2 || len(args) == 3):
		if servers.ValidID(args[1]) != nil {
			fmt.Fprintln(stderr, "hub servers op: invalid server id")
			return 2
		}
		method, path = http.MethodGet, "/host/servers/"+args[1]+"/op"
		if len(args) == 3 {
			path += "?op_id=" + url.QueryEscape(args[2])
		}
	default:
		fmt.Fprintln(stderr, serversUsage)
		return 2
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		fmt.Fprintln(stderr, "the Hub isn't running")
		return serversUnanswered
	}
	c := &http.Client{Timeout: serversTimeout(args[0]), Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, "http://hub"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Op == "dial" {
			fmt.Fprintln(stderr, "the Hub isn't running")
		} else if errors.As(err, &ue) && ue.Timeout() {
			id := "<id>"
			if len(args) > 1 {
				id = args[1]
			}
			fmt.Fprintf(stderr, "the Hub is still working: see `hub servers op %s`\n", id)
		} else {
			fmt.Fprintf(stderr, "the Hub's answer was cut: %v\n", err)
		}
		return serversUnanswered
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		fmt.Fprintln(stderr, strings.TrimSpace(string(out)))
		if res.StatusCode >= 500 {
			return serversUnanswered
		}
		return 1
	}
	if args[0] != "add-cluster-node" {
		stdout.Write(out)
		return 0
	}
	// The code alone on stdout; the rest of the answer on stderr.
	var a map[string]json.RawMessage
	var code string
	if json.Unmarshal(out, &a) != nil || json.Unmarshal(a["code"], &code) != nil || code == "" {
		fmt.Fprintln(stderr, "the Hub answered no join code")
		return 1
	}
	delete(a, "code")
	rest, _ := json.Marshal(a)
	fmt.Fprintln(stderr, string(rest))
	fmt.Fprintln(stdout, code)
	return 0
}

// nodeadmURLFromEnv is HUB_NODEADM_URL on Kubernetes (contract §20.2):
// unset = nodeadm.DefaultURL; else an https URL without a path, query or
// credentials (the Hub's client certificate goes there).
func nodeadmURLFromEnv(getenv func(string) string) (string, error) {
	v := strings.TrimSpace(getenv("HUB_NODEADM_URL"))
	if v == "" {
		return nodeadm.DefaultURL, nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("HUB_NODEADM_URL must be https://<host>[:<port>] (default %s)", nodeadm.DefaultURL)
	}
	return strings.TrimSuffix(v, "/"), nil
}
