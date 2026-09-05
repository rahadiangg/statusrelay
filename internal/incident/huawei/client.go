package huawei

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
)

// Endpoint paths, relative to the configured base URL.
//
// The base URL carries a path prefix that selects the dataset. These are joined
// with httpx.JoinPath rather than resolved as absolute paths, because resolving
// "/v1/shd/..." against a base would drop that prefix and silently return a
// different site's data at HTTP 200.
const (
	pathCurrentEvents = "v1/shd/current-events"
	pathPastEvents    = "v1/shd/past-events"
	pathHistoryEvents = "v1/shd/history-events"
	pathServices      = "v1/shd/services"
	pathStatistic     = "v1/shd/event-statistic"
	pathEventReports  = "v1/shd/event-reports"
)

// catalogueLimit is sent on every services request.
//
// It is not an optimisation. Omitting it yields the server default of 1000
// rows, which returns only 9 of the 17 regions — at HTTP 200, with no error and
// no pagination hint. The regions that vanish are silently unmonitorable.
const catalogueLimit = 10000

// doer is the HTTP surface the client needs, so tests can substitute one.
type doer interface {
	GetJSON(ctx context.Context, url string, v any) (httpx.Result, error)
}

// client talks to one Huawei status host, with an optional mirror.
type client struct {
	http   doer
	base   string
	mirror string

	mu      sync.Mutex
	usedAlt bool // sticky preference for the mirror after a failure
}

// get fetches a path from the primary host, falling back to the mirror.
//
// Failover covers transport failures and WAF blocks, which are host-specific:
// the two hosts serve identical data from different edge addresses, so a block
// on one is frequently not a block on the other. It deliberately does NOT cover
// ErrBadRequest, ErrEndpointGone or ErrSchemaDrift — those are the same on both
// hosts, and retrying them elsewhere just doubles the damage.
func (c *client) get(ctx context.Context, path string, q url.Values, v any) (httpx.Result, error) {
	hosts := c.hostOrder()
	var lastErr error
	for i, h := range hosts {
		u, err := httpx.JoinPath(h, path, q)
		if err != nil {
			return httpx.Result{}, err
		}
		res, err := c.http.GetJSON(ctx, u, v)
		if err == nil {
			c.rememberHost(i)
			return res, nil
		}
		lastErr = err
		if !failoverWorthy(err) {
			return httpx.Result{}, err
		}
	}
	return httpx.Result{}, lastErr
}

func failoverWorthy(err error) bool {
	return errors.Is(err, incident.ErrUpstream) ||
		errors.Is(err, incident.ErrBlocked) ||
		errors.Is(err, incident.ErrNotJSON)
}

func (c *client) hostOrder() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mirror == "" {
		return []string{c.base}
	}
	if c.usedAlt {
		return []string{c.mirror, c.base}
	}
	return []string{c.base, c.mirror}
}

// rememberHost makes the mirror sticky once it has worked, so a persistent
// block on the primary does not cost a failed attempt on every single poll.
// It resets whenever the primary succeeds again.
func (c *client) rememberHost(idx int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.usedAlt = idx != 0
}

func (c *client) currentEvents(ctx context.Context) ([]wireEvent, httpx.Result, error) {
	var ws []wireEvent
	// No query parameters at all. In particular never region_code: this API
	// accepts it, ignores it, and returns the full unfiltered list at HTTP 200,
	// so a server-side filter would look like it worked and never filter.
	res, err := c.get(ctx, pathCurrentEvents, nil, &ws)
	return ws, res, err
}

func (c *client) pastEvents(ctx context.Context) ([]wireEvent, httpx.Result, error) {
	var ws []wireEvent
	res, err := c.get(ctx, pathPastEvents, nil, &ws)
	return ws, res, err
}

// historyEvents fetches a time window.
//
// start is REQUIRED. Omitting it does not error: the endpoint returns an empty
// array at HTTP 200, which is indistinguishable from "nothing happened in that
// window". The parameter names are snake_case on the wire.
func (c *client) historyEvents(ctx context.Context, start, end time.Time) ([]wireEvent, error) {
	if start.IsZero() {
		return nil, fmt.Errorf("%w: history requires a start time; omitting it returns an empty list, not an error",
			incident.ErrBadRequest)
	}
	q := url.Values{"start_time": {formatTime(start)}}
	if !end.IsZero() {
		q.Set("end_time", formatTime(end))
	}
	var ws []wireEvent
	_, err := c.get(ctx, pathHistoryEvents, q, &ws)
	return ws, err
}

func (c *client) services(ctx context.Context) ([]wireServiceRow, error) {
	q := url.Values{"offset": {"0"}, "limit": {fmt.Sprint(catalogueLimit)}}
	var rows []wireServiceRow
	_, err := c.get(ctx, pathServices, q, &rows)
	return rows, err
}

func (c *client) statistic(ctx context.Context) (wireStatistic, error) {
	var s wireStatistic
	_, err := c.get(ctx, pathStatistic, nil, &s)
	return s, err
}
