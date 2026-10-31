package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// Event is the subset of an Engine API event the Hub uses.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	TimeNano int64 `json:"timeNano"`
}

// Events streams events matching f until ctx is cancelled or the connection
// drops; fn is called for each event. It returns the terminating error
// (ctx.Err() on cancellation).
func (c *Client) Events(ctx context.Context, f Filters, fn func(Event)) error {
	q := url.Values{}
	if len(f) > 0 {
		q.Set("filters", f.encode())
	}
	resp, err := c.do(ctx, c.stream, http.MethodGet, "/events", q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		fn(ev)
	}
}
