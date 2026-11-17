package usage

import "time"

// Point is one sample at its time, with the container's restart count
// and OOM state then (the doctor's oom_killed) and the container it came
// from (a recreated container continues the same key's ring).
type Point struct {
	T         time.Time
	S         Sample
	Restarts  int
	OOMKilled bool
	ID        string
}

// Ring keeps a container's last n points (not safe for concurrent use:
// the sampler guards it).
type Ring struct {
	buf  []Point
	next int
	full bool
}

// NewRing is an empty ring of n points (n < 1: RingSize).
func NewRing(n int) *Ring {
	if n < 1 {
		n = RingSize
	}
	return &Ring{buf: make([]Point, n)}
}

// Add appends p, dropping the oldest when full.
func (r *Ring) Add(p Point) {
	r.buf[r.next] = p
	r.next++
	if r.next == len(r.buf) {
		r.next, r.full = 0, true
	}
}

// Len is the number of points held.
func (r *Ring) Len() int {
	if r.full {
		return len(r.buf)
	}
	return r.next
}

// Points are the points, oldest first (a copy).
func (r *Ring) Points() []Point {
	if !r.full {
		return append([]Point(nil), r.buf[:r.next]...)
	}
	out := make([]Point, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	return append(out, r.buf[:r.next]...)
}

// Since are the points at or after t, oldest first.
func (r *Ring) Since(t time.Time) []Point {
	ps := r.Points()
	for i, p := range ps {
		if !p.T.Before(t) {
			return ps[i:]
		}
	}
	return nil
}

// Last is the newest point (false when empty).
func (r *Ring) Last() (Point, bool) {
	if r.Len() == 0 {
		return Point{}, false
	}
	i := r.next - 1
	if i < 0 {
		i = len(r.buf) - 1
	}
	return r.buf[i], true
}
