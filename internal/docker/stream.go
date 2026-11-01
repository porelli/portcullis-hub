package docker

// limitedBuffer is an io.Writer that keeps at most max bytes and records
// whether anything was dropped. It never reports a short write, so
// stdcopy keeps draining (and discarding) the rest of the stream.
type limitedBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.max - len(b.buf); room < len(p) {
		if room > 0 {
			b.buf = append(b.buf, p[:room]...)
		}
		b.truncated = true
		return n, nil
	}
	b.buf = append(b.buf, p...)
	return n, nil
}
