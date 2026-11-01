package docker

import (
	"bytes"
	"context"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
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
	rc, err := c.api.ContainerLogs(ctx, id, client.ContainerLogsOptions{
		ShowStdout: true, ShowStderr: true, Tail: strconv.Itoa(tail), Timestamps: timestamps})
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	out := &limitedBuffer{max: maxLogBytes}
	// Non-TTY output is multiplexed; TTY output is raw.
	if tty {
		_, err = io.Copy(out, rc)
	} else {
		_, err = stdcopy.StdCopy(out, out, rc)
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
