package signinhistory

import (
	"slices"
	"time"
)

// Merge is the lists' entries newest first (stable: equal times keep the
// lists' order, then each list's), at most limit (limit < 1: none).
func Merge(limit int, lists ...[]Entry) []Entry {
	out := []Entry{}
	if limit < 1 {
		return out
	}
	for _, l := range lists {
		out = append(out, l...)
	}
	slices.SortStableFunc(out, func(a, b Entry) int { return b.Time.Compare(a.Time) })
	return out[:min(len(out), limit)]
}

// Within keeps the entries with since <= time < before.
func Within(es []Entry, since, before time.Time) []Entry {
	out := make([]Entry, 0, len(es))
	for _, e := range es {
		if !e.Time.Before(since) && e.Time.Before(before) {
			out = append(out, e)
		}
	}
	return out
}
