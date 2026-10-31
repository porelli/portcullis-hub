package docker

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Stream identifiers in the multiplexed (non-TTY) attach/logs format.
const (
	Stdin  = 0
	Stdout = 1
	Stderr = 2
)

// maxFrame bounds a single frame so a corrupt header can't make us allocate
// gigabytes.
const maxFrame = 16 << 20

// Demux splits Docker's multiplexed stream (8-byte header
// [stream, 0, 0, 0, size uint32 BE] followed by size bytes) into stdout and
// stderr. Either writer may be the same, or nil to discard. Returns nil at a
// clean EOF between frames.
func Demux(r io.Reader, stdout, stderr io.Writer) error {
	br := bufio.NewReader(r)
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			if err == io.ErrUnexpectedEOF {
				return errors.New("docker stream: truncated frame header")
			}
			return err
		}
		size := binary.BigEndian.Uint32(hdr[4:])
		if size > maxFrame {
			return fmt.Errorf("docker stream: frame of %d bytes exceeds limit", size)
		}
		var w io.Writer
		switch hdr[0] {
		case Stdin, Stdout:
			w = stdout
		case Stderr:
			w = stderr
		default:
			return fmt.Errorf("docker stream: unknown stream id %d", hdr[0])
		}
		if w == nil {
			w = io.Discard
		}
		if _, err := io.CopyN(w, br, int64(size)); err != nil {
			if err == io.EOF {
				return errors.New("docker stream: truncated frame")
			}
			return err
		}
	}
}

// limitedBuffer is an io.Writer that keeps at most max bytes and records
// whether anything was dropped.
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
