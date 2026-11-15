package docker

import (
	"context"

	"github.com/portcullis/hub/internal/runtime"

	"github.com/moby/moby/client"
)

// Event is runtime.Event.
type Event = runtime.Event

// Events streams events matching f until ctx is cancelled or the connection
// drops; fn is called for each event. It returns the terminating error
// (ctx.Err() on cancellation, io.EOF when the daemon ends the stream).
func (c *Client) Events(ctx context.Context, f Filters, fn func(Event)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the SDK's reader goroutine
	res := c.api.Events(ctx, client.EventsListOptions{Filters: f.sdk()})
	for {
		select {
		case m := <-res.Messages:
			ev := Event{Type: string(m.Type), Action: string(m.Action), TimeNano: m.TimeNano}
			ev.Actor.ID, ev.Actor.Attributes = m.Actor.ID, m.Actor.Attributes
			fn(ev)
		case err := <-res.Err:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
}
