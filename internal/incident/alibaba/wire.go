// Package alibaba adapts the Alibaba Cloud Health Status page's public but
// undocumented JSON API to the incident.Source contract.
//
// The endpoints are the ones the vendor's own status page calls, take no
// authentication, and answer HTTP 200 for almost everything — including their
// own errors. The behaviours the code below defends against were each verified
// against the live API rather than assumed:
//
//   - Errors are an HTTP 200 with {"success":false,"code":400|500|502} in the
//     body. The HTTP status carries no information at all.
//   - A detail lookup for an id that does not exist is {"success":true,
//     "data":[]}: indistinguishable from a fetch that found nothing.
//   - The per-region history endpoint honours regionId but answers a bogus
//     region with a full page of empty days at success:true. A wrong region
//     code monitors nothing forever and reports healthy.
//   - The region catalogue endpoint refuses requests without a Referer header
//     ("not on the whitelist", code 502). The incident endpoints do not care.
//   - A renamed endpoint answers with a 302 to an error page on another host.
//   - Product and region names are Chinese unless Accept-Language says
//     otherwise; the server honours it.
//   - The history list is paginated and abbreviated: products, regions and
//     progress are null there and only the detail endpoint carries them.
package alibaba

import (
	"bytes"
	"encoding/json"
	"html"
	"strconv"
	"strings"
	"time"
)

// envelope is the wrapper every endpoint uses. Data is left raw so the caller
// decodes it into the shape that endpoint promises, and so a null Data is
// visible as a null rather than as a decode error.
type envelope struct {
	Data     json.RawMessage `json:"data"`
	Total    int             `json:"total"`
	Info     string          `json:"info"`
	Code     int             `json:"code"`
	Success  bool            `json:"success"`
	HTTPCode int             `json:"httpCode"`
}

// wireEvent is one incident as the API sends it.
//
// The same struct decodes the abbreviated rows of the history list (where the
// three slices are null) and the full rows of the detail endpoint. Timestamps
// decode through msTime, which records a malformed value instead of failing,
// so one bad field on one record can never cost the whole page.
type wireEvent struct {
	ID        flexInt `json:"id"`
	Title     string  `json:"title"`
	EventType string  `json:"eventType"`

	StartTime      msTime `json:"startTime"`
	EndTime        msTime `json:"endTime"`
	LastUpdateTime msTime `json:"lastUpdateTime"`

	Products     []wireProduct `json:"products"`
	Regions      []wireRegion  `json:"regions"`
	EventUpdates []wireUpdate  `json:"eventUpdates"`
}

type wireProduct struct {
	ProductID   string `json:"productId"`
	ProductName string `json:"productName"`
}

type wireRegion struct {
	RegionID   string `json:"regionId"`
	RegionName string `json:"regionName"`
}

type wireUpdate struct {
	ID          flexInt `json:"id"`
	DisplayType string  `json:"displayType"`
	Content     string  `json:"content"` // HTML fragment
	PublishTime msTime  `json:"publishTime"`
}

// wireZone is one entry of the region catalogue: a zone and its regions.
type wireZone struct {
	Zone struct {
		ZoneID   string `json:"zoneId"`
		ZoneName string `json:"zoneName"`
	} `json:"zone"`
	RegionList []wireRegion `json:"regionList"`
}

// wirePeriodDay is one day bucket of the per-region history. Only the event
// ids are read; the bodies stay raw so the shape can drift without breaking
// the one probe that depends on this endpoint.
type wirePeriodDay struct {
	Date                msTime `json:"date"`
	ProductStatusDetail struct {
		EventDetails map[string]json.RawMessage `json:"eventDetails"`
	} `json:"productStatusDetail"`
}

// msTime is an epoch-milliseconds timestamp that may be null.
//
// A malformed value sets Bad rather than returning an error, for the same
// reason huawei keeps timestamps as strings: losing a real outage to one bad
// field is far worse than carrying a zero time with an anomaly attached.
type msTime struct {
	T   time.Time
	Set bool
	Bad bool
}

func (m *msTime) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			m.Bad = true
			return nil
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		b = []byte(s)
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		m.Bad = true
		return nil
	}
	v, err := n.Int64()
	if err != nil {
		fl, ferr := n.Float64()
		if ferr != nil {
			m.Bad = true
			return nil
		}
		v = int64(fl)
	}
	if v < 0 {
		m.Bad = true
		return nil
	}
	m.T, m.Set = time.UnixMilli(v).UTC(), true
	return nil
}

// flexInt accepts a JSON number or a JSON string holding a number.
//
// Duplicated from huawei rather than shared: adapters are independent by
// design, and forty lines is cheaper than a dependency between them.
type flexInt struct {
	Value int64
	Set   bool
}

func (f *flexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		f.Value, f.Set = n, true
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	v, err := n.Int64()
	if err != nil {
		fl, ferr := n.Float64()
		if ferr != nil {
			return err
		}
		v = int64(fl)
	}
	f.Value, f.Set = v, true
	return nil
}

func (f flexInt) String() string { return strconv.FormatInt(f.Value, 10) }

// stripHTML reduces a progress fragment to plain text.
//
// Progress entries arrive as HTML ("<p>17:25 All affected ... recovered.</p>").
// Notifications and the fingerprint want text, and they want the SAME text on
// every poll, so this is deliberately a fixed, simple transformation: block
// boundaries become newlines, every other tag vanishes, entities are decoded,
// runs of whitespace collapse.
//
// ponytail: naive tag stripper; swap for x/net/html if content ever carries
// <script>/<style> whose bodies must not leak into a page.
func stripHTML(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for {
		lt := strings.IndexByte(s, '<')
		if lt < 0 {
			b.WriteString(s)
			break
		}
		gt := strings.IndexByte(s[lt:], '>')
		if gt < 0 {
			// An unclosed '<' is text, not markup.
			b.WriteString(s)
			break
		}
		b.WriteString(s[:lt])
		tag := strings.ToLower(strings.TrimSpace(s[lt+1 : lt+gt]))
		tag = strings.TrimPrefix(tag, "/")
		if name, _, _ := strings.Cut(tag, " "); name == "br" || name == "br/" || name == "p" || name == "li" || name == "div" {
			b.WriteByte('\n')
		}
		s = s[lt+gt+1:]
	}
	return collapseSpace(html.UnescapeString(b.String()))
}

// collapseSpace folds runs of whitespace to one space, or to one newline when
// the run contained a newline, and trims the ends.
func collapseSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	pendingNL, pendingSP := false, false
	for _, r := range s {
		switch r {
		case '\n', '\r':
			pendingNL = true
		case ' ', '\t', ' ':
			pendingSP = true
		default:
			if b.Len() > 0 {
				if pendingNL {
					b.WriteByte('\n')
				} else if pendingSP {
					b.WriteByte(' ')
				}
			}
			pendingNL, pendingSP = false, false
			b.WriteRune(r)
		}
	}
	return b.String()
}

// formatMS renders a time as the epoch-milliseconds string the period
// endpoint expects for endTime.
func formatMS(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }
