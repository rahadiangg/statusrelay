package alibaba

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
)

// Endpoint paths, relative to the configured base URL.
//
// The "International" suffix is what the vendor's international site sends.
// Today the unsuffixed names serve the same corpus from the same backend, so
// unlike the Huawei path prefix it is not currently load-bearing — but it is
// the documented contract of the site we read, and the day the two diverge is
// not a day anyone will announce.
const (
	pathInProgress = "listEventInProgressInternational"
	pathHistory    = "listHistoryEventInternational"
	pathDetail     = "getEventDetailInternational"
	pathPeriod     = "listProductStatusInPeriodInternational"
	pathZones      = "listProductRegionInAllZone"
)

// historyPageSize is sent on every history request. The server's default page
// size is undocumented; sending an explicit one is how we know what we asked
// for when comparing against the envelope's total.
const historyPageSize = 200

// Referer is the header value the catalogue endpoint requires.
//
// listProductRegionInAllZone answers {"code":502,"info":"不在白名单"} ("not on
// the whitelist") without it, at HTTP 200. The incident endpoints do not check
// it, which is exactly why it is easy to ship an adapter that fetches
// incidents fine and then cannot validate a single region code.
const Referer = "https://status.alibabacloud.com/"

// doer is the HTTP surface the client needs, so tests can substitute one.
type doer interface {
	GetJSON(ctx context.Context, url string, v any) (httpx.Result, error)
}

// client talks to one Alibaba status host. There is no mirror: the vendor
// serves one backend behind one hostname.
type client struct {
	http doer
	base string
}

// get fetches a path, checks the envelope, and decodes its data into v.
//
// The envelope check is the whole point of this function. httpx classifies by
// HTTP status and by a vendor-specific error_code field; this upstream uses
// neither, so without this step a {"success":false} body decodes as "zero
// incidents".
func (c *client) get(ctx context.Context, path string, q url.Values, v any) (envelope, error) {
	u, err := httpx.JoinPath(c.base, path, q)
	if err != nil {
		return envelope{}, err
	}
	var env envelope
	if _, err := c.http.GetJSON(ctx, u, &env); err != nil {
		return envelope{}, err
	}
	if err := classifyEnvelope(env); err != nil {
		return env, fmt.Errorf("%s: %w", path, err)
	}
	if v == nil || len(env.Data) == 0 || bytes.Equal(bytes.TrimSpace(env.Data), []byte("null")) {
		return env, nil
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		// A partial decode must never yield a partial result: half a list
		// silently means "fewer incidents than there really are".
		return env, fmt.Errorf("%w: %s: decoding data: %v", incident.ErrSchemaDrift, path, err)
	}
	return env, nil
}

// classifyEnvelope maps the vendor's in-body status to a sentinel error.
func classifyEnvelope(env envelope) error {
	if env.Success {
		return nil
	}
	switch {
	case env.Code == 400:
		// The request was wrong, not unlucky. Never retried.
		return fmt.Errorf("%w: upstream reports code 400 %q", incident.ErrBadRequest, env.Info)
	case env.Code == 502 && strings.Contains(env.Info, "白名单"):
		// "Not on the whitelist": the Referer header is missing. Retrying
		// would repeat the same refusal forever; failing loud at startup is
		// what makes it get fixed.
		return fmt.Errorf("%w: upstream refused the request as not whitelisted (missing Referer header): %q",
			incident.ErrBadRequest, env.Info)
	case env.Code == 0 && env.HTTPCode == 0:
		// No envelope fields at all: the body was JSON but not this API's.
		return fmt.Errorf("%w: response carried no envelope", incident.ErrSchemaDrift)
	default:
		// Anything else is treated as transient. If it persists the poller's
		// stale-after alarm surfaces it; treating it as fatal would turn one
		// bad backend response into a lost poll with no retry.
		return fmt.Errorf("%w: upstream reports code %d %q", incident.ErrUpstream, env.Code, env.Info)
	}
}

// inProgress returns the open list and the vendor's own count of it.
func (c *client) inProgress(ctx context.Context) ([]wireEvent, int, error) {
	var ws []wireEvent
	env, err := c.get(ctx, pathInProgress, nil, &ws)
	return ws, env.Total, err
}

// history returns one page of resolved events, newest first, and the total
// across all pages. Both paging parameters are always sent: the server's
// default page size is unknown, and a total that disagrees with what we asked
// for is only meaningful when we know what we asked for.
func (c *client) history(ctx context.Context, page, size int) ([]wireEvent, int, error) {
	q := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	var ws []wireEvent
	env, err := c.get(ctx, pathHistory, q, &ws)
	return ws, env.Total, err
}

// detail fetches the full record for one id.
//
// An unknown id is not an error upstream: it is {"success":true,"data":[]}.
// That is reported as found=false so the caller can decide what an absence
// means, which depends on whether the id came from a list five seconds ago.
func (c *client) detail(ctx context.Context, id string) (wireEvent, bool, error) {
	var ws []wireEvent
	if _, err := c.get(ctx, pathDetail, url.Values{"eventId": {id}}, &ws); err != nil {
		return wireEvent{}, false, err
	}
	switch len(ws) {
	case 0:
		return wireEvent{}, false, nil
	case 1:
		return ws[0], true, nil
	default:
		return wireEvent{}, false, fmt.Errorf("%w: detail for event %s returned %d records",
			incident.ErrSchemaDrift, id, len(ws))
	}
}

// period fetches the per-region day buckets ending at end.
//
// regionID is refused locally when empty because the interesting failure is
// the other one: a region that does not exist is answered with a full page of
// empty days at success:true, so nothing after this point can tell a typo
// from a quiet month.
func (c *client) period(ctx context.Context, regionID string, end time.Time, days int) ([]wirePeriodDay, error) {
	if strings.TrimSpace(regionID) == "" {
		return nil, fmt.Errorf("%w: period requires a regionId", incident.ErrBadRequest)
	}
	q := url.Values{
		"regionId": {regionID},
		"endTime":  {formatMS(end)},
		"numOfDay": {strconv.Itoa(days)},
	}
	var ds []wirePeriodDay
	_, err := c.get(ctx, pathPeriod, q, &ds)
	return ds, err
}

func (c *client) zones(ctx context.Context) ([]wireZone, error) {
	var zs []wireZone
	_, err := c.get(ctx, pathZones, nil, &zs)
	return zs, err
}
