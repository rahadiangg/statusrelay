package tencent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

var testEpoch = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

// goldenDoc loads a captured API response. Fixtures are verbatim captures
// where the real API produces the shape, and derived from a real capture where
// it does not (an ongoing incident has never been observed live).
func goldenDoc(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("fixture %s is empty; a golden test reading nothing passes vacuously", name)
	}
	return b
}

func decodeHistory(t *testing.T, name string) []wireEvent {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(goldenDoc(t, name), &env); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	var h wireHistory
	if err := json.Unmarshal(env.Response.Data, &h); err != nil {
		t.Fatalf("decoding %s data: %v", name, err)
	}
	return h.List
}

func newMapper() *mapper { return &mapper{sourceID: "tencent-intl", now: testEpoch} }

func mapFixture(t *testing.T, name string) (open, resolved []incident.Record, m *mapper) {
	t.Helper()
	m = newMapper()
	open, resolved = m.mapEvents(decodeHistory(t, name))
	return open, resolved, m
}

func hasAnomaly(ws []incident.Warning, kind string) bool {
	for _, w := range ws {
		if w.Kind == kind {
			return true
		}
	}
	return false
}

func findRec(t *testing.T, recs []incident.Record, code string) incident.Record {
	t.Helper()
	for _, r := range recs {
		if r.Key.ProviderID == code {
			return r
		}
	}
	t.Fatalf("record %s not found", code)
	return incident.Record{}
}

// The reference incident, verbatim from the live API.
func TestMapReferenceIncident(t *testing.T) {
	open, resolved, m := mapFixture(t, "history_12m.json")
	if len(open) != 0 || len(resolved) != 5 {
		t.Fatalf("got %d open, %d resolved, want 0 and 5", len(open), len(resolved))
	}
	if len(m.anomalies) != 0 {
		t.Errorf("anomalies on a clean capture: %+v", m.anomalies)
	}
	r := findRec(t, resolved, "93a75460e1115154b8cad11828c34ba7")
	for _, tc := range []struct {
		name      string
		got, want any
	}{
		{"source", r.Key.SourceID, "tencent-intl"},
		{"title", r.Title, "Problems with Cloud Block Storage etc. detected in Seoul"},
		{"title lang", r.TitleLang, "en"},
		{"status", r.Status, incident.StatusResolved},
		{"severity", r.Severity, incident.SeverityUnknown},
		{"raw severity", r.RawSeverity, "normal"},
		{"started (UTC, no zone marker on the wire)", r.StartedAt, time.Date(2026, 4, 21, 13, 38, 0, 0, time.UTC)},
		{"ended", r.EndedAt, time.Date(2026, 4, 21, 20, 10, 0, 0, time.UTC)},
		{"updated", r.UpdatedAt, time.Date(2026, 4, 21, 20, 20, 1, 0, time.UTC)},
		{"global", r.Global, false},
		{"scope len", len(r.Scope), 1},
		{"region", r.Scope[0].RegionCode, "ap-seoul"},
		{"region name", r.Scope[0].RegionName, "Seoul"},
		{"services", len(r.Scope[0].Services), 3},
		{"service sorted first", r.Scope[0].Services[0].ID, "cbs"},
		{"service abbr upper-cased for Filter", r.Scope[0].Services[0].Abbr, "CBS"},
		{"service name trimmed", r.Scope[0].Services[2].Name, "Tencent Cloud Lighthouse"},
		{"fingerprint set", r.FP.Content != "", true},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// A platform-wide event is published under the non-regional pseudo-region.
// It must map to Global, not to a region called "non-regional" that no
// operator's filter would ever name.
func TestMapNonRegionalIsGlobal(t *testing.T) {
	_, resolved, m := mapFixture(t, "history_12m.json")
	r := findRec(t, resolved, "8649c64bb761ad90b7944eeef1e279b6")
	if !r.Global || len(r.Scope) != 0 {
		t.Errorf("got Global=%v scope=%v, want Global with no scope", r.Global, r.Scope)
	}
	if hasAnomaly(m.anomalies, incident.AnomalyNullScope) {
		t.Error("non-regional is a real published shape, not a null scope")
	}
}

func TestMapZeroDurationEventKeepsEndedAt(t *testing.T) {
	_, resolved, _ := mapFixture(t, "history_12m.json")
	r := findRec(t, resolved, "c635650cb610f484ec29e59067dc8e90")
	if r.EndedAt.IsZero() || !r.EndedAt.Equal(r.StartedAt) {
		t.Errorf("got started=%v ended=%v, want equal and non-zero", r.StartedAt, r.EndedAt)
	}
}

func TestMapStatusAndShapeZoo(t *testing.T) {
	open, resolved, m := mapFixture(t, "history_zoo.json")
	all := append(append([]incident.Record{}, open...), resolved...)
	get := func(suffix string) incident.Record { return findRec(t, all, "0000000000000000000000000000"+suffix) }

	for _, tc := range []struct {
		name   string
		code   string
		status incident.Status
		sev    incident.Severity
		raw    string
	}{
		{"info notice is open and Info", "ab00", incident.StatusOpen, incident.SeverityInfo, "info"},
		{"string status decodes", "ab01", incident.StatusOpen, incident.SeverityUnknown, "unnormal"},
		{"unknown status fails open", "ab02", incident.StatusOpen, incident.SeverityUnknown, "7"},
		{"ongoing exercise is Info", "ab03", incident.StatusOpen, incident.SeverityInfo, "exercise"},
		{"resolved exercise stays resolved", "ab04", incident.StatusResolved, incident.SeverityInfo, "exercise"},
		{"disabled row is kept", "ab13", incident.StatusOpen, incident.SeverityUnknown, "unnormal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := get(tc.code)
			if r.Status != tc.status || r.Severity != tc.sev || r.RawSeverity != tc.raw {
				t.Errorf("got %v/%v/%q, want %v/%v/%q", r.Status, r.Severity, r.RawSeverity, tc.status, tc.sev, tc.raw)
			}
		})
	}

	t.Run("unknown status is warned", func(t *testing.T) {
		if !hasAnomaly(m.anomalies, incident.AnomalyUnknownStatus) {
			t.Error("missing unknown_status anomaly")
		}
	})
	t.Run("blank title falls back and is warned", func(t *testing.T) {
		r := get("ab05")
		if r.TitleLang != "none" || r.Title == "" {
			t.Errorf("got %q/%q", r.Title, r.TitleLang)
		}
		if !hasAnomaly(m.anomalies, incident.AnomalyEmptyDescription) {
			t.Error("missing empty_description anomaly")
		}
	})
	t.Run("unkeyed row is dropped and counted", func(t *testing.T) {
		for _, r := range all {
			if r.Title == "unkeyed" {
				t.Error("row without EventCode must not become a record")
			}
		}
		if m.unkeyed != 1 || !hasAnomaly(m.anomalies, "unkeyed_event") {
			t.Errorf("unkeyed=%d anomalies=%+v", m.unkeyed, m.anomalies)
		}
	})
	t.Run("global-only scope", func(t *testing.T) {
		if r := get("ab07"); !r.Global || len(r.Scope) != 0 {
			t.Errorf("got Global=%v scope=%v", r.Global, r.Scope)
		}
	})
	t.Run("mixed non-regional and real region keeps the real one", func(t *testing.T) {
		r := get("ab08")
		if r.Global || len(r.Scope) != 1 || r.Scope[0].RegionCode != "ap-guangzhou" {
			t.Errorf("got Global=%v scope=%+v", r.Global, r.Scope)
		}
	})
	t.Run("empty region list is Global and warned", func(t *testing.T) {
		if r := get("ab09"); !r.Global {
			t.Error("want Global")
		}
		if !hasAnomaly(m.anomalies, incident.AnomalyNullScope) {
			t.Error("missing null_scope anomaly")
		}
	})
	t.Run("bad timestamp keeps the record", func(t *testing.T) {
		if r := get("ab10"); !r.StartedAt.IsZero() {
			t.Errorf("got %v, want zero", r.StartedAt)
		}
		if !hasAnomaly(m.anomalies, incident.AnomalyBadTimestamp) {
			t.Error("missing bad_timestamp anomaly")
		}
	})
	t.Run("future start is warned", func(t *testing.T) {
		if !hasAnomaly(m.anomalies, incident.AnomalyFutureTimestamp) {
			t.Error("missing future_timestamp anomaly")
		}
	})
	t.Run("open row has no EndedAt", func(t *testing.T) {
		if r := get("ab00"); !r.EndedAt.IsZero() {
			t.Errorf("got %v", r.EndedAt)
		}
	})
	t.Run("duplicate code: first wins, warned", func(t *testing.T) {
		n := 0
		for _, r := range all {
			if r.Key.ProviderID == "0000000000000000000000000000ab14" {
				n++
				if r.Title != "dup" {
					t.Errorf("got %q, want the first occurrence", r.Title)
				}
			}
		}
		if n != 1 || !hasAnomaly(m.anomalies, incident.AnomalyDuplicateID) {
			t.Errorf("n=%d anomalies=%+v", n, m.anomalies)
		}
	})
}

func TestMapEventsIsDeterministic(t *testing.T) {
	a1, r1, _ := mapFixture(t, "history_zoo.json")
	a2, r2, _ := mapFixture(t, "history_zoo.json")
	for i := range a1 {
		if !a1[i].FP.Equal(a2[i].FP) || a1[i].Key != a2[i].Key {
			t.Errorf("open[%d] differs between identical inputs", i)
		}
	}
	for i := range r1 {
		if !r1[i].FP.Equal(r2[i].FP) {
			t.Errorf("resolved[%d] differs between identical inputs", i)
		}
	}
}

func TestMapProgress(t *testing.T) {
	load := func(name string) []wireProgress {
		var env envelope
		if err := json.Unmarshal(goldenDoc(t, name), &env); err != nil {
			t.Fatal(err)
		}
		var p wireProgressList
		if err := json.Unmarshal(env.Response.Data, &p); err != nil {
			t.Fatal(err)
		}
		return p.List
	}
	t.Run("verbatim timeline is chronological", func(t *testing.T) {
		m := newMapper()
		us := m.mapProgress("x", load("progress_seoul.json"))
		if len(us) != 5 || us[0].At.After(us[4].At) || us[0].Lang != "en" || us[0].Hash == "" {
			t.Errorf("got %+v", us)
		}
		if hasAnomaly(m.anomalies, incident.AnomalyProgressOutOfOrder) {
			t.Error("verbatim capture flagged out of order")
		}
	})
	t.Run("out of order is sorted and warned", func(t *testing.T) {
		m := newMapper()
		us := m.mapProgress("x", load("progress_out_of_order.json"))
		for i := 1; i < len(us); i++ {
			if us[i].At.Before(us[i-1].At) {
				t.Error("not sorted")
			}
		}
		if !hasAnomaly(m.anomalies, incident.AnomalyProgressOutOfOrder) {
			t.Error("missing progress_out_of_order anomaly")
		}
	})
	t.Run("blank entry is dropped", func(t *testing.T) {
		if us := newMapper().mapProgress("x", load("progress_blank_entry.json")); len(us) != 5 {
			t.Errorf("got %d updates, want 5", len(us))
		}
	})
	t.Run("empty is nil", func(t *testing.T) {
		if us := newMapper().mapProgress("x", nil); us != nil {
			t.Errorf("got %v", us)
		}
	})
}

func TestParseTime(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Time
		ok   bool
	}{
		{"2026-04-21 13:38:00", time.Date(2026, 4, 21, 13, 38, 0, 0, time.UTC), true},
		{"  2026-04-21 13:38:00 ", time.Date(2026, 4, 21, 13, 38, 0, 0, time.UTC), true},
		{"", time.Time{}, true},
		{"2026-04-21T13:38:00Z", time.Time{}, false},
		{"2026-04-21", time.Time{}, false},
		{"garbage", time.Time{}, false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseTime(tc.in)
			if ok != tc.ok || !got.Equal(tc.want) {
				t.Errorf("got %v,%v want %v,%v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
