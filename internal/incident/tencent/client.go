package tencent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/incident/httpx"
)

// Endpoint paths, relative to the base URL. Joined with httpx.JoinPath so a
// base URL carrying a path prefix keeps it.
const (
	pathHistory  = "v1/api/ops/DescribeHistoryEventList"
	pathProgress = "v1/api/ops/DescribeHistoryEventProgress"
	pathRegions  = "v1/api/status/DescribeRegions"
)

// Paging constants for the history list.
//
// The corpus is single digits per year, so one page is the norm. The cap is
// there so a Total that keeps growing mid-walk (or a server that ignores
// PageNumber) cannot turn one poll into an unbounded crawl; hitting it marks
// the snapshot incomplete rather than pretending the walk finished.
const (
	pageSize     = 100
	maxPages     = 20
	lookbackMons = 12
)

// belongSite is sent on every request because the dashboard sends it. The
// server ignores it (0, 2 and absent all return the same data), so it is not
// a dataset selector; it is kept so our requests are indistinguishable from
// the browser's and a future change to its meaning shows up in the canary.
const belongSite = "1"

// doer is the HTTP surface the client needs, so tests can substitute one.
type doer interface {
	GetJSON(ctx context.Context, url string, v any) (httpx.Result, error)
}

type client struct {
	http doer
	base string
}

// get fetches one endpoint and unwraps the envelope.
//
// Every failure this API can express arrives as HTTP 200 with an Error object,
// so the shared httpx classifier never sees it. The mapping here is what turns
// "you called a renamed endpoint" into ErrEndpointGone instead of a decode
// error that reads like schema drift.
func (c *client) get(ctx context.Context, path string, q url.Values, v any) error {
	if q == nil {
		q = url.Values{}
	}
	q.Set("BelongSite", belongSite)
	u, err := httpx.JoinPath(c.base, path, q)
	if err != nil {
		return err
	}
	var env envelope
	if _, err := c.http.GetJSON(ctx, u, &env); err != nil {
		return err
	}
	if e := env.Response.Error; e != nil {
		if e.Code == "InternalError" && strings.Contains(e.Message, "rpc name") {
			return fmt.Errorf("%w: %s: %s", incident.ErrEndpointGone, e.Code, e.Message)
		}
		return fmt.Errorf("%w: %s: %s", incident.ErrUpstream, e.Code, e.Message)
	}
	data := bytes.TrimSpace(env.Response.Data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return fmt.Errorf("%w: %s returned neither Data nor Error", incident.ErrSchemaDrift, path)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: decoding %s: %v", incident.ErrSchemaDrift, path, err)
	}
	return nil
}

// historyEvents walks every page of the lookback window.
//
// truncated reports that the walk stopped before Total was reached, so the
// caller can mark the snapshot incomplete. A Total that shrinks between pages
// is treated the same way: the list moved under us and a row may have fallen
// through the gap.
func (c *client) historyEvents(ctx context.Context) (rows []wireEvent, truncated bool, err error) {
	total := -1
	for page := 1; page <= maxPages; page++ {
		q := url.Values{
			"PageSize":   {strconv.Itoa(pageSize)},
			"PageNumber": {strconv.Itoa(page)},
			"GapMonth":   {strconv.Itoa(lookbackMons)},
		}
		var h wireHistory
		if err := c.get(ctx, pathHistory, q, &h); err != nil {
			return nil, false, err
		}
		if total >= 0 && h.Total < total {
			return append(rows, h.List...), true, nil
		}
		total = h.Total
		rows = append(rows, h.List...)
		if len(rows) >= total || len(h.List) == 0 {
			// Fewer rows than Total with an empty page means the server has
			// nothing more to give; report it rather than loop to the cap.
			return rows, len(rows) < total, nil
		}
	}
	return rows, true, nil
}

func (c *client) progress(ctx context.Context, code string) ([]wireProgress, error) {
	var p wireProgressList
	err := c.get(ctx, pathProgress, url.Values{"HistoryEventCode": {code}}, &p)
	return p.List, err
}

func (c *client) regions(ctx context.Context) (wireRegions, error) {
	var r wireRegions
	err := c.get(ctx, pathRegions, nil, &r)
	return r, err
}
