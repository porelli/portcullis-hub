package docker

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxLogBytes bounds what is read per container.
const maxLogBytes = 8 << 20

// Logs returns the last tail lines (stdout+stderr) of one container,
// demultiplexed. Each line keeps the daemon's RFC3339Nano timestamp prefix
// when timestamps is true.
func (c *Client) Logs(ctx context.Context, id string, tail int, timestamps bool) ([]byte, error) {
	tty, err := c.tty(ctx, id)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"stdout": {"1"},
		"stderr": {"1"},
		"tail":   {strconv.Itoa(tail)},
	}
	if timestamps {
		q.Set("timestamps", "1")
	}
	resp, err := c.do(ctx, c.stream, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs", q, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := &limitedBuffer{max: maxLogBytes}
	body := io.Reader(resp.Body)
	// Non-TTY output is always multiplexed (API >= 1.42 also says so in
	// Content-Type); TTY output is raw.
	if !tty || resp.Header.Get("Content-Type") == "application/vnd.docker.multiplexed-stream" {
		err = Demux(body, out, out)
	} else {
		_, err = io.Copy(out, body)
	}
	return out.buf, err
}

// LogLine is one timestamped line from a container.
type LogLine struct {
	Time   time.Time
	Source string
	Text   string
}

// MergeLogs interleaves timestamped log output of several containers by
// time (stable for equal stamps), prefixing each line with its source the
// way `docker compose logs` does, and keeps the last tail lines overall.
func MergeLogs(sources map[string][]byte, tail int) []byte {
	var lines []LogLine
	width := 0
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
		if len(name) > width {
			width = len(name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		for _, raw := range strings.Split(strings.TrimRight(string(sources[name]), "\n"), "\n") {
			if raw == "" {
				continue
			}
			ll := LogLine{Source: name, Text: raw}
			if sp := strings.IndexByte(raw, ' '); sp > 0 {
				if t, err := time.Parse(time.RFC3339Nano, raw[:sp]); err == nil {
					ll.Time, ll.Text = t, raw[sp+1:]
				}
			}
			lines = append(lines, ll)
		}
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Time.Before(lines[j].Time) })
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	var b bytes.Buffer
	for _, l := range lines {
		if len(sources) > 1 {
			b.WriteString(l.Source)
			b.WriteString(strings.Repeat(" ", width-len(l.Source)))
			b.WriteString("  | ")
		}
		b.WriteString(l.Text)
		b.WriteByte('\n')
	}
	return b.Bytes()
}
