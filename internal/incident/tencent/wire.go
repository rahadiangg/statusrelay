// Package tencent is the Tencent Cloud Health Dashboard adapter.
//
// The dashboard at status.tencentcloud.com is a browser app over an
// unauthenticated JSON API on the same host. The API answers HTTP 200 to
// everything — errors, unknown regions, unknown event codes — so most of this
// package is about telling those apart from "nothing happened".
package tencent

import (
	"encoding/json"
	"strings"
	"time"
)

// envelope is the outer shape every endpoint shares. Exactly one of Error and
// Data is populated; both are checked because neither absence is an error at
// the HTTP layer.
type envelope struct {
	Response struct {
		RequestID string          `json:"RequestId"`
		Error     *wireError      `json:"Error"`
		Data      json.RawMessage `json:"Data"`
	} `json:"Response"`
}

type wireError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// Event status values, shared by history rows and progress entries.
//
// Lifted from the dashboard's own bundle, where the enum is a string; the JSON
// carries a number. json.Number accepts both, so a future flip does not break
// decoding — it would only show up as an unknown value, which alerts.
const (
	statusInfo     = "0"
	statusResolved = "1"
	statusOngoing  = "2"
)

// wireHistory is DescribeHistoryEventList.Data.
type wireHistory struct {
	Total int         `json:"Total"`
	List  []wireEvent `json:"List"`
}

type wireEvent struct {
	EventCode  string        `json:"EventCode"`
	Title      string        `json:"Title"`
	StartTime  string        `json:"StartTime"`
	EndTime    string        `json:"EndTime"`
	UpdateTime string        `json:"UpdateTime"`
	Status     json.Number   `json:"Status"`
	IsExercise bool          `json:"IsExercise"`
	IsEnable   bool          `json:"IsEnable"`
	Products   []wireProduct `json:"ProductList"`
	Regions    []wireRegion  `json:"RegionList"`
	TimeRegion string        `json:"TimeRegion"`
}

type wireProduct struct {
	ID   string `json:"ProductId"`
	Name string `json:"ProductName"`
}

type wireRegion struct {
	ID       string `json:"RegionId"`
	Name     string `json:"RegionName"`
	EventsIn bool   `json:"EventsIn"` // only on DescribeRegions
}

// wireProgressList is DescribeHistoryEventProgress.Data.
type wireProgressList struct {
	List []wireProgress `json:"ProgressList"`
}

type wireProgress struct {
	Code      string      `json:"ProgressCode"`
	OccurTime string      `json:"OccurTime"`
	Status    json.Number `json:"Status"`
	Content   string      `json:"Content"`
}

// wireRegions is DescribeRegions.Data.
type wireRegions struct {
	Areas []struct {
		Name    string       `json:"AreaName"`
		Regions []wireRegion `json:"RegionList"`
	} `json:"AreaDetailList"`
}

// timeLayout is the only shape this API emits. Values are UTC despite the
// absence of a zone marker: the dashboard renders "13:38:00" with
// TimeRegion=Asia/Seoul as 22:38 (UTC+09:00), and the RSS feed's dc:date for
// the same entry ends in Z.
const timeLayout = "2006-01-02 15:04:05"

// parseTime returns (zero, true) for an empty value: an open event has no end
// yet, and that is not a malformed timestamp.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, true
	}
	t, err := time.ParseInLocation(timeLayout, s, time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
