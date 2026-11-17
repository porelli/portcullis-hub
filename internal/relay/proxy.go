package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is one relay container (env, contract §17.2; pre-flight P15:
// one listener per distinct loadbalancer.server.port of the service).
type Config struct {
	// Ports are RELAY_LISTEN's ports; each forwards to the same port of
	// the service on the worker.
	Ports []int
	// Target is RELAY_TARGET, the pseudo-host <instance>.<service>.relay.
	Target string
	// Link is RELAY_LINK, link's data CONNECT listener (<ip>:3129).
	Link string
	// Token is PORTCULLIS_RELAY_TOKEN, the instance's bearer (never logged).
	Token string
	// App / Server are the offline page's labels.
	App, Server string
}

// MaxPorts bounds RELAY_LISTEN.
const MaxPorts = 16

var targetRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*\.[a-zA-Z0-9][a-zA-Z0-9_.-]*\.relay$`)

// ParseListen reads RELAY_LISTEN: a comma list of :<port> (1–65535),
// distinct, at most MaxPorts.
func ParseListen(v string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(strings.TrimPrefix(p, ":"))
		if !strings.HasPrefix(p, ":") || err != nil || n < 1 || n > 65535 || seen[n] {
			return nil, fmt.Errorf("RELAY_LISTEN: %q must be :<port>, each port once", p)
		}
		seen[n] = true
		out = append(out, n)
	}
	if len(out) == 0 || len(out) > MaxPorts {
		return nil, fmt.Errorf("RELAY_LISTEN: 1–%d ports", MaxPorts)
	}
	return out, nil
}

// Validate checks c (before anything listens).
func (c Config) Validate() error {
	switch {
	case len(c.Ports) == 0:
		return errors.New("no port to listen on")
	case !targetRe.MatchString(c.Target) || len(c.Target) > 200:
		return errors.New("RELAY_TARGET must be <instance>.<service>.relay")
	case c.Token == "" || len(c.Token) > 256 || strings.ContainsAny(c.Token, " \t\r\n"):
		return errors.New("PORTCULLIS_RELAY_TOKEN must be set (one token, no spaces)")
	}
	if _, _, err := net.SplitHostPort(c.Link); err != nil {
		return errors.New("RELAY_LINK must be <host>:<port>")
	}
	return nil
}

// dialer opens a CONNECT tunnel through link to target:port with the
// bearer, and returns the tunnelled connection (bytes link already sent
// past the response are kept).
func (c Config) dialer(port int) func(ctx context.Context, _, _ string) (net.Conn, error) {
	target := net.JoinHostPort(c.Target, strconv.Itoa(port))
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", c.Link)
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			conn.SetDeadline(dl)
		} else {
			conn.SetDeadline(time.Now().Add(15 * time.Second))
		}
		req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: Bearer " + c.Token + "\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("link refused the tunnel: %s", resp.Status)
		}
		conn.SetDeadline(time.Time{})
		return &bufConn{Conn: conn, r: br}, nil
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// forwarded are the headers Traefik sets that pass through unchanged
// (ReverseProxy with Rewrite would drop them).
var forwarded = []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server", "X-Real-Ip", "Forwarded"}

// Handler is the relay for one listener port: a ReverseProxy (WebSocket
// and other upgrades included) whose transport only ever dials link's
// CONNECT; request cookies filtered, response cookies host-only; any dial
// failure answers the offline page.
func (c Config) Handler(port int) http.Handler {
	offline := OfflinePage(cleanLabel(c.App), cleanLabel(c.Server))
	tr := &http.Transport{DialContext: c.dialer(port), MaxIdleConns: 32, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 0, ExpectContinueTimeout: time.Second, ForceAttemptHTTP2: false}
	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = net.JoinHostPort(c.Target, strconv.Itoa(port))
			r.Out.Host = r.In.Host
			for _, k := range forwarded {
				if v := r.In.Header.Values(k); len(v) > 0 {
					r.Out.Header[k] = append([]string(nil), v...)
				}
			}
			FilterRequestCookies(r.Out.Header)
		},
		ModifyResponse: func(resp *http.Response) error {
			FilterResponseCookies(resp.Header, resp.Request.Host)
			return nil
		},
		ErrorHandler:  func(w http.ResponseWriter, r *http.Request, err error) { offline(w, r) },
		FlushInterval: -1,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(&informational{ResponseWriter: w}, r)
	})
}

// informational strips Set-Cookie from every 1xx response but 101
// (ReverseProxy forwards 1xx such as 103 Early Hints without
// ModifyResponse; 101 goes through ModifyResponse's filter).
type informational struct{ http.ResponseWriter }

func (i *informational) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		i.Header().Del("Set-Cookie")
	}
	i.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the connection (Hijack for
// upgrades, Flush for streams).
func (i *informational) Unwrap() http.ResponseWriter { return i.ResponseWriter }

func (i *informational) Flush() {
	if f, ok := i.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Listen opens exactly the configured ports (on every address of the
// relay's networks: Traefik reaches it on portcullis-proxy) and nothing
// else.
func (c Config) Listen() ([]net.Listener, error) {
	var out []net.Listener
	for _, p := range c.Ports {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err != nil {
			for _, l := range out {
				l.Close()
			}
			return nil, err
		}
		out = append(out, ln)
	}
	return out, nil
}

// NewServer is a relay listener's http.Server.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 5 * time.Minute, MaxHeaderBytes: 1 << 20}
}
