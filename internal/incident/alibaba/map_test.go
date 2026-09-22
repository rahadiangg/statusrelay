package alibaba

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

func goldenDoc(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading golden file %s: %v", name, err)
	}
	if len(b) == 0 {
		t.Fatalf("golden file %s is empty", name)
	}
	return b
}

// decodeEvents unwraps a fixture's envelope into event rows.
func decodeEvents(t *testing.T, name string) []wireEvent {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(goldenDoc(t, name), &env); err != nil {
		t.Fatalf("decoding envelope %s: %v", name, err)
	}
	var ws []wireEvent
	if err := json.Unmarshal(env.Data, &ws); err != nil {
		t.Fatalf("decoding events %s: %v", name, err)
	}
	return ws
}

func newMapper() *mapper { return &mapper{sourceID: "alibaba-intl", page: pageURL(DefaultBaseURL)} }

func mapFixture(t *testing.T, name string, status incident.Status) ([]incident.Record, []incident.Warning) {
	t.Helper()
	m := newMapper()
	return m.mapEvents(decodeEvents(t, name), status), m.anomalies
}

func hasAnomaly(ws []incident.Warning, kind string) bool {
	for _, w := range ws {
		if w.Kind == kind {
			return true
		}
	}
	return false
}

func TestMapDetail35(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35.json", incident.StatusResolved)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if len(warns) != 0 {
		t.Errorf("got anomalies %v, want none", warns)
	}
	r := recs[0]
	if r.Key != (incident.Key{SourceID: "alibaba-intl", ProviderID: "35"}) {
		t.Errorf("key = %v", r.Key)
	}
	if r.TitleLang != "en" || r.Titles["en"] != r.Title || r.Title == "" {
		t.Errorf("title = %q lang %q", r.Title, r.TitleLang)
	}
	if r.Severity != incident.SeverityMajor || r.RawSeverity != "ALARM" {
		t.Errorf("severity = %v raw %q, want major/ALARM", r.Severity, r.RawSeverity)
	}
	if r.Status != incident.StatusResolved {
		t.Errorf("status = %v, want resolved", r.Status)
	}
	wantStart := time.UnixMilli(1785214500000).UTC()
	wantEnd := time.UnixMilli(1785230700000).UTC()
	wantUpd := time.UnixMilli(1785230829000).UTC()
	if !r.StartedAt.Equal(wantStart) || !r.EndedAt.Equal(wantEnd) || !r.UpdatedAt.Equal(wantUpd) {
		t.Errorf("times = %v %v %v, want %v %v %v", r.StartedAt, r.EndedAt, r.UpdatedAt, wantStart, wantEnd, wantUpd)
	}
	if r.StartedAt.Location() != time.UTC {
		t.Errorf("StartedAt location = %v, want UTC", r.StartedAt.Location())
	}
	if r.Global {
		t.Error("Global = true, want false for a regional event")
	}
	if len(r.Scope) != 1 || r.Scope[0].RegionCode != "ap-southeast-5" || r.Scope[0].RegionName != "Indonesia (Jakarta)" {
		t.Fatalf("scope = %+v", r.Scope)
	}
	if got := len(r.Scope[0].Services); got != 15 {
		t.Errorf("got %d services, want 15", got)
	}
	// Services are sorted by id and the abbreviation is the upper-cased id,
	// which is what the config's services filter compares against.
	if s := r.Scope[0].Services[0]; s.ID != "ads" || s.Abbr != "ADS" || s.Name != "AnalyticDB for MySQL" {
		t.Errorf("first service = %+v", s)
	}
	if len(r.Updates) != 5 {
		t.Fatalf("got %d updates, want 5", len(r.Updates))
	}
	for i := 1; i < len(r.Updates); i++ {
		if r.Updates[i].At.Before(r.Updates[i-1].At) {
			t.Errorf("updates not chronological at %d", i)
		}
	}
	if u := r.Updates[4]; u.Text != "17:25 All affected cloud products have been recovered." || u.Lang != "en" || u.Hash == "" {
		t.Errorf("last update = %+v", u)
	}
	if r.FP.Content == "" || r.FP.Scope == "" || r.FP.Progress == "" {
		t.Errorf("fingerprint incomplete: %+v", r.FP)
	}
}

func TestMapEmptyArrayIsZeroRecords(t *testing.T) {
	recs, warns := mapFixture(t, "in-progress_empty.json", incident.StatusOpen)
	if len(recs) != 0 || len(warns) != 0 {
		t.Errorf("got %d records %v, want none", len(recs), warns)
	}
}

func TestMapSeverity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		want    incident.Severity
		anomaly bool
	}{
		{"alarm is major", "detail_35.json", incident.SeverityMajor, false},
		{"notification is info", "detail_35_notification.json", incident.SeverityInfo, false},
		{"unknown type still alerts", "detail_35_unknown_type.json", incident.SeverityUnknown, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, warns := mapFixture(t, tc.fixture, incident.StatusResolved)
			if recs[0].Severity != tc.want {
				t.Errorf("got %v, want %v", recs[0].Severity, tc.want)
			}
			if hasAnomaly(warns, incident.AnomalyUnknownSeverity) != tc.anomaly {
				t.Errorf("unknown_severity anomaly = %v, want %v", !tc.anomaly, tc.anomaly)
			}
			if tc.anomaly {
				f := incident.Filter{IncludeGlobal: true, MinSeverity: incident.SeverityCritical}
				if !f.Matches(recs[0]) {
					t.Error("an ungradeable incident must pass a critical-only filter")
				}
			}
		})
	}
}

func TestMapNullRegionsIsGlobal(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35_null_regions.json", incident.StatusResolved)
	r := recs[0]
	if !r.Global || len(r.Scope) != 0 {
		t.Errorf("Global = %v scope = %v, want global with no scope", r.Global, r.Scope)
	}
	if !hasAnomaly(warns, incident.AnomalyNullScope) {
		t.Errorf("want null_scope anomaly, got %v", warns)
	}
}

func TestMapNonRegionalIsGlobalWithScope(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35_non_regional.json", incident.StatusResolved)
	r := recs[0]
	if !r.Global {
		t.Error("Global = false, want true for a non-regional event")
	}
	if len(r.Scope) != 2 || r.Scope[0].RegionCode != "ap-southeast-5" || r.Scope[1].RegionCode != nonRegional {
		t.Errorf("scope = %+v, want both regions sorted by code", r.Scope)
	}
	if hasAnomaly(warns, incident.AnomalyNullScope) {
		t.Error("non-regional is a published region, not a null scope")
	}
	// A Jakarta-only deployment still hears about it via include_global.
	f := incident.Filter{Regions: map[string]bool{"ap-northeast-2": true}, IncludeGlobal: true}
	if !f.Matches(r) {
		t.Error("a non-regional event must match a deployment watching another region")
	}
}

func TestMapNullUpdatesIsNoUpdates(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35_null_updates.json", incident.StatusResolved)
	if len(recs[0].Updates) != 0 || len(warns) != 0 {
		t.Errorf("updates = %v warns = %v", recs[0].Updates, warns)
	}
}

func TestMapDropsBlankUpdate(t *testing.T) {
	recs, _ := mapFixture(t, "detail_35_blank_update.json", incident.StatusResolved)
	if got := len(recs[0].Updates); got != 5 {
		t.Errorf("got %d updates, want 5 (the blank one dropped)", got)
	}
}

func TestMapNewestFirstUpdatesAreNotFlagged(t *testing.T) {
	_, warns := mapFixture(t, "detail_35.json", incident.StatusResolved)
	if hasAnomaly(warns, incident.AnomalyProgressOutOfOrder) {
		t.Error("the vendor's newest-first order is expected, not an anomaly")
	}
}

func TestMapShuffledUpdatesAreFlaggedAndSorted(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35_shuffled_updates.json", incident.StatusResolved)
	if !hasAnomaly(warns, incident.AnomalyProgressOutOfOrder) {
		t.Errorf("want progress_out_of_order, got %v", warns)
	}
	base, _ := mapFixture(t, "detail_35.json", incident.StatusResolved)
	if !recs[0].FP.Equal(base[0].FP) {
		t.Error("shuffled updates must fingerprint identically once sorted")
	}
}

func TestMapStatusConflict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		status  incident.Status
		endZero bool
	}{
		{"open row with endTime stays open", "in-progress_open_with_endtime.json", incident.StatusOpen, false},
		{"resolved row without endTime stays resolved", "history_no_endtime.json", incident.StatusResolved, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, warns := mapFixture(t, tc.fixture, tc.status)
			r := recs[len(recs)-1] // 35 sorts last in the history page
			if r.Status != tc.status {
				t.Errorf("status = %v, want %v", r.Status, tc.status)
			}
			if r.EndedAt.IsZero() != tc.endZero {
				t.Errorf("EndedAt zero = %v, want %v", r.EndedAt.IsZero(), tc.endZero)
			}
			if !hasAnomaly(warns, incident.AnomalyStatusConflict) {
				t.Errorf("want status_conflict, got %v", warns)
			}
		})
	}
}

func TestMapNoConflictOnAgreement(t *testing.T) {
	_, warns := mapFixture(t, "in-progress_one_open.json", incident.StatusOpen)
	if hasAnomaly(warns, incident.AnomalyStatusConflict) {
		t.Errorf("an open row without endTime is not a conflict: %v", warns)
	}
	_, warns = mapFixture(t, "history_page.json", incident.StatusResolved)
	if hasAnomaly(warns, incident.AnomalyStatusConflict) {
		t.Errorf("a resolved row with endTime is not a conflict: %v", warns)
	}
}

func TestMapNullLastUpdateIsZeroMtime(t *testing.T) {
	recs, _ := mapFixture(t, "in-progress_one_open.json", incident.StatusOpen)
	if !recs[0].UpdatedAt.IsZero() {
		t.Errorf("UpdatedAt = %v, want zero", recs[0].UpdatedAt)
	}
}

func TestMapStringAndFloatMillisAccepted(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35_string_ms.json", incident.StatusResolved)
	base, _ := mapFixture(t, "detail_35.json", incident.StatusResolved)
	if len(warns) != 0 {
		t.Errorf("got anomalies %v, want none", warns)
	}
	if recs[0].Key != base[0].Key || !recs[0].FP.Equal(base[0].FP) {
		t.Error("a quoted id and quoted/float timestamps must map identically to the numeric form")
	}
}

func TestMapBadMillisKeepsRecord(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35_bad_ms.json", incident.StatusResolved)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1; a bad timestamp must never drop an incident", len(recs))
	}
	if !recs[0].StartedAt.IsZero() || !recs[0].UpdatedAt.IsZero() {
		t.Errorf("bad times must be zero, got %v %v", recs[0].StartedAt, recs[0].UpdatedAt)
	}
	n := 0
	for _, w := range warns {
		if w.Kind == incident.AnomalyBadTimestamp {
			n++
		}
	}
	if n != 3 {
		t.Errorf("got %d bad_timestamp anomalies, want 3 (start, lastUpdate, one progress)", n)
	}
	if got := len(recs[0].Updates); got != 5 {
		t.Errorf("got %d updates, want 5", got)
	}
}

func TestMapEmptyTitleYieldsPlaceholder(t *testing.T) {
	recs, warns := mapFixture(t, "detail_35_no_title.json", incident.StatusResolved)
	if recs[0].Title != "(untitled #35)" || recs[0].TitleLang != "none" {
		t.Errorf("title = %q lang %q", recs[0].Title, recs[0].TitleLang)
	}
	if !hasAnomaly(warns, incident.AnomalyEmptyDescription) {
		t.Errorf("want empty_description, got %v", warns)
	}
}

func TestMapDuplicateIDsResolveDeterministically(t *testing.T) {
	var first []incident.Record
	for i := 0; i < 25; i++ {
		recs, warns := mapFixture(t, "history_dup_35.json", incident.StatusResolved)
		if len(recs) != 4 {
			t.Fatalf("got %d records, want 4", len(recs))
		}
		if !hasAnomaly(warns, incident.AnomalyDuplicateID) {
			t.Fatalf("want duplicate_id, got %v", warns)
		}
		if first == nil {
			first = recs
			continue
		}
		for j := range recs {
			if !recs[j].FP.Equal(first[j].FP) {
				t.Fatalf("run %d record %d differs from run 0", i, j)
			}
		}
	}
}

func TestMapOrdersRecordsNumericallyByID(t *testing.T) {
	recs, _ := mapFixture(t, "history_page.json", incident.StatusResolved)
	want := []string{"32", "33", "34", "35"}
	for i, r := range recs {
		if r.Key.ProviderID != want[i] {
			t.Fatalf("record %d id = %s, want %s", i, r.Key.ProviderID, want[i])
		}
	}
}

func TestMapIsDeterministicAcrossRuns(t *testing.T) {
	base, _ := mapFixture(t, "detail_34.json", incident.StatusResolved)
	for i := 0; i < 50; i++ {
		recs, _ := mapFixture(t, "detail_34.json", incident.StatusResolved)
		if !recs[0].FP.Equal(base[0].FP) || recs[0].Title != base[0].Title {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestPickDuplicatePrefersNewerThenLonger(t *testing.T) {
	t0 := time.UnixMilli(1000).UTC()
	a := incident.Record{UpdatedAt: t0, Updates: []incident.Update{{}}}
	b := incident.Record{UpdatedAt: t0.Add(time.Second)}
	if got := pickDuplicate(a, b); !got.UpdatedAt.Equal(b.UpdatedAt) {
		t.Error("newer mtime must win")
	}
	c := incident.Record{UpdatedAt: t0, Updates: []incident.Update{{}, {}}}
	if got := pickDuplicate(a, c); len(got.Updates) != 2 {
		t.Error("more progress must win on equal mtime")
	}
	if got := pickDuplicate(a, incident.Record{UpdatedAt: t0, Updates: []incident.Update{{}}}); len(got.Updates) != 1 {
		t.Error("payload order must win on a full tie")
	}
	if !lessID("9", "13") || lessID("b", "a") {
		t.Error("lessID must be numeric for numbers and lexical otherwise")
	}
}

func TestStripHTML(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"paragraph", "<p>a</p>", "a"},
		{"break", "a<br>b<br/>c<BR />d", "a\nb\nc\nd"},
		{"nested and entity", "<p><b>x</b> &amp; y</p>", "x & y"},
		{"entities", "&lt;tag&gt;&nbsp;it&#39;s", "<tag> it's"},
		{"unclosed lt is text", "5 < 6 and 7", "5 < 6 and 7"},
		{"collapse whitespace", "  a \t b\n\n c  ", "a b\nc"},
		{"paragraphs become one newline", "<p>a</p>\n<p>b</p>", "a\nb"},
		{"attributes", `<a href="x">link</a>`, "link"},
		{"empty after strip", "<p> </p>", ""},
		{"plain", "already text", "already text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripHTML(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMsTime(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		wantSet  bool
		wantBad  bool
		wantMS   int64
	}{
		{"number", `1785214500000`, true, false, 1785214500000},
		{"quoted number", `"1785214500000"`, true, false, 1785214500000},
		{"float", `1785214500000.7`, true, false, 1785214500000},
		{"null", `null`, false, false, 0},
		{"empty string", `""`, false, false, 0},
		{"garbage string", `"yesterday"`, false, true, 0},
		{"object", `{"x":1}`, false, true, 0},
		{"negative", `-1`, false, true, 0},
		{"zero", `0`, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m msTime
			if err := json.Unmarshal([]byte(tc.in), &m); err != nil {
				t.Fatalf("unmarshal must never fail, got %v", err)
			}
			if m.Set != tc.wantSet || m.Bad != tc.wantBad {
				t.Errorf("got set=%v bad=%v, want set=%v bad=%v", m.Set, m.Bad, tc.wantSet, tc.wantBad)
			}
			if tc.wantSet && m.T.UnixMilli() != tc.wantMS {
				t.Errorf("got %d ms, want %d", m.T.UnixMilli(), tc.wantMS)
			}
		})
	}
}

func TestFlexInt(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     int64
		wantSet  bool
		wantErr  bool
	}{
		{"number", `35`, 35, true, false},
		{"string", `"35"`, 35, true, false},
		{"float", `35.9`, 35, true, false},
		{"null", `null`, 0, false, false},
		{"empty", `""`, 0, false, false},
		{"word", `"abc"`, 0, false, true},
		{"object", `{}`, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f flexInt
			err := json.Unmarshal([]byte(tc.in), &f)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if f.Value != tc.want || f.Set != tc.wantSet {
				t.Errorf("got %d set=%v, want %d set=%v", f.Value, f.Set, tc.want, tc.wantSet)
			}
		})
	}
}

func TestFormatMSRoundTrips(t *testing.T) {
	ts := time.UnixMilli(1785400000000).UTC()
	if got := formatMS(ts); got != "1785400000000" {
		t.Errorf("got %q, want 1785400000000", got)
	}
}
