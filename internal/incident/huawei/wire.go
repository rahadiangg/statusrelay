// Package huawei adapts the Huawei Cloud Service Health Dashboard's public but
// undocumented JSON API to the incident.Source contract.
//
// The endpoints take no authentication and are the same ones the vendor's own
// status page calls. Everything defensive here traces to a verified behaviour of
// that API rather than to general caution; the specific behaviours are named at
// the code they justify.
package huawei

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// wireEvent is one incident exactly as the API sends it.
//
// Timestamps are kept as strings here and parsed during mapping. That split is
// deliberate: an unparseable timestamp on one record must not fail the decode of
// the whole response, because losing a real outage is far worse than carrying
// one zero timestamp with an anomaly flag attached.
type wireEvent struct {
	EventID   flexInt `json:"event_id"`
	EventLvl  flexInt `json:"event_level"`
	EventType flexInt `json:"event_type"` // always 1; never read by the vendor's own frontend
	DescZH    string  `json:"desc_zh"`
	DescEN    string  `json:"desc_en"`

	// OccurTime is when the vendor PUBLISHED the record, not when the fault
	// began. On the one incident on record, detection preceded publication by
	// about sixteen minutes.
	OccurTime string `json:"event_occur_time"`

	// LastUpdate is present only on resolved records. Open records carry no
	// mtime at all, which is why change detection cannot rest on it.
	LastUpdate string `json:"last_update_time"`

	HasReport bool `json:"has_report"`

	Progress []wireProgress `json:"event_progress"`

	// ExtInfos may be null or absent. That is a real shape — a platform-wide
	// event published with no region attached — not a parse failure.
	ExtInfos []wireExtInfo `json:"event_ext_infos"`
}

type wireProgress struct {
	ZH   string `json:"progress_zh"`
	EN   string `json:"progress_en"`
	Time string `json:"progress_occur_time"`
}

type wireExtInfo struct {
	RegionID   string        `json:"region_id"`
	RegionCode string        `json:"region_code"`
	RegionZH   string        `json:"region_zh_name"`
	RegionEN   string        `json:"region_en_name"`
	Services   []wireService `json:"impacted_services"`
}

type wireService struct {
	ID   string `json:"service_id"`
	ZH   string `json:"service_zh_name"`
	EN   string `json:"service_en_name"`
	Abbr string `json:"service_abbr"`
}

// wireServiceRow is one row of the region x service catalogue.
type wireServiceRow struct {
	RegionCode  string `json:"region_code"`
	RegionZH    string `json:"region_zh_name"`
	RegionEN    string `json:"region_en_name"`
	LocaleEN    string `json:"locale_en"`
	ServiceCode string `json:"service_code"`
	ServiceID   string `json:"service_id"`
	ServiceZH   string `json:"service_zh_name"`
	ServiceEN   string `json:"service_en_name"`
	ServiceAbbr string `json:"service_abbr"`
	OnlineTime  string `json:"online_time"`
	// OfflineTime is non-empty for retired services. There is no health field
	// anywhere in this payload: the catalogue says what EXISTS, never what is
	// working.
	OfflineTime string `json:"offline_time"`
}

// wireStatistic is the vendor's own count, used purely as a cross-check against
// the lists we fetched separately.
type wireStatistic struct {
	Unresolved int `json:"unresolved_count"`
	History    int `json:"history_count"`
	Total      int `json:"total"`
}

// flexInt accepts a JSON number or a JSON string holding a number.
//
// event_id is an integer today. Widening it to a string later would be an
// upstream change we could not influence and would break every poll at once, so
// accepting both now costs one type and removes that failure entirely.
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
		// A float where an integer was promised is still a usable id once
		// truncated, and refusing it would drop the record entirely.
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

// parseTime accepts the timestamp shapes this API has been observed to emit and
// reports failure rather than guessing.
//
// The documented shape is RFC3339 with a Z suffix. The tolerated variants below
// are all real-world drift we would rather absorb than crash on; anything else
// yields ok=false so the caller can flag an anomaly and keep the record.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",       // zone omitted entirely
		"2006-01-02 15:04:05Z07:00", // space instead of T
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			// A timestamp with no zone is assumed UTC rather than local: the
			// process timezone must never change how an incident is ordered.
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// formatTime renders a timestamp in the only shape the history endpoint
// accepts. Milliseconds, numeric offsets and date-only values are all rejected
// upstream with HTTP 400, so this is not a stylistic choice.
func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
