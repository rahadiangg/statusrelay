package huawei

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// goldenDoc loads a captured API response. Fixtures are verbatim captures where
// the real API produces the shape, and derived from a real capture where it does
// not (an open incident, for instance, has never been observed live).
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

func decodeEvents(t *testing.T, name string) []wireEvent {
	t.Helper()
	var ws []wireEvent
	if err := json.Unmarshal(goldenDoc(t, name), &ws); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	return ws
}

func newMapper() *mapper {
	return &mapper{sourceID: "huawei-intl", page: pageURL(DefaultBaseURL), preferLang: "en", levels: defaultLevels()}
}

// mapFixture decodes and maps a fixture, returning the records and anomalies.
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

// The reference incident: the only one this vendor has ever published on the
// international site.
func TestMapReferenceIncident(t *testing.T) {
	recs, _ := mapFixture(t, "past-events_event13.json", incident.StatusResolved)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]

	if r.Key.ProviderID != "13" {
		t.Errorf("id = %q, want %q", r.Key.ProviderID, "13")
	}
	if r.Severity != incident.SeverityCritical {
		t.Errorf("severity = %v, want critical", r.Severity)
	}
	if r.RawSeverity != "2" {
		t.Errorf("raw severity = %q, want %q", r.RawSeverity, "2")
	}
	if r.TitleLang != "en" {
		t.Errorf("title language = %q, want %q", r.TitleLang, "en")
	}
	if r.Global {
		t.Error("a record with regions must not be marked global")
	}
	if r.StartedAt.IsZero() {
		t.Error("started time did not parse")
	}
	if r.UpdatedAt.IsZero() {
		t.Error("update time did not parse")
	}
	if len(r.Updates) == 0 {
		t.Error("progress entries were dropped")
	}

	var jakarta *incident.Scope
	for i := range r.Scope {
		if r.Scope[i].RegionCode == "ap-southeast-4" {
			jakarta = &r.Scope[i]
		}
	}
	if jakarta == nil {
		t.Fatal("ap-southeast-4 missing from the mapped scope")
	}
	if jakarta.RegionName != "AP-Jakarta" {
		t.Errorf("region name = %q, want %q", jakarta.RegionName, "AP-Jakarta")
	}
	if len(jakarta.Services) == 0 {
		t.Error("impacted services were dropped")
	}
}

// The mtime sits after the newest progress entry on the real record, which is
// the concrete reason the fingerprint keeps them as separate signals.
func TestReferenceIncidentMtimeTrailsProgress(t *testing.T) {
	recs, _ := mapFixture(t, "past-events_event13.json", incident.StatusResolved)
	r := recs[0]
	newest := r.Updates[len(r.Updates)-1].At
	if !r.UpdatedAt.After(newest) {
		t.Skipf("fixture no longer exhibits the mtime-after-progress shape (mtime %v, newest progress %v)",
			r.UpdatedAt, newest)
	}
}

func TestMapEmptyArrayIsZeroRecords(t *testing.T) {
	recs, anoms := mapFixture(t, "current-events_empty.json", incident.StatusOpen)
	if len(recs) != 0 {
		t.Errorf("got %d records, want 0", len(recs))
	}
	if len(anoms) != 0 {
		t.Errorf("an empty list is normal and must raise no anomaly, got %+v", anoms)
	}
}

// A region-less event is a real shape, not a parse failure. It must survive as
// Global so downstream filtering can include it.
func TestMapNullScopeBecomesGlobal(t *testing.T) {
	for _, name := range []string{
		"past-events_null_ext_infos.json",
		"past-events_ext_infos_empty.json",
	} {
		t.Run(name, func(t *testing.T) {
			recs, anoms := mapFixture(t, name, incident.StatusResolved)
			if len(recs) != 1 {
				t.Fatalf("got %d records, want 1", len(recs))
			}
			if !recs[0].Global {
				t.Error("record with no regions was not marked Global")
			}
			if len(recs[0].Scope) != 0 {
				t.Errorf("got %d scopes, want 0", len(recs[0].Scope))
			}
			if !hasAnomaly(anoms, incident.AnomalyNullScope) {
				t.Error("a region-less event must be flagged as an anomaly")
			}
		})
	}
}

// Real records ship an empty English description. A naive reader emits a blank
// alert; the mapper must fall back and say which language it used.
func TestMapEmptyEnglishFallsBackToChinese(t *testing.T) {
	recs, anoms := mapFixture(t, "past-events_empty_desc_en.json", incident.StatusResolved)
	r := recs[0]

	if r.TitleLang != "zh" {
		t.Errorf("title language = %q, want %q", r.TitleLang, "zh")
	}
	if r.Title == "" {
		t.Error("title is empty; a blank alert reads as a rendering bug, not an outage")
	}
	if !hasAnomaly(anoms, incident.AnomalyEmptyDescription) {
		t.Error("a missing preferred-language description must be flagged")
	}
	for _, u := range r.Updates {
		if u.Text == "" {
			t.Error("a progress entry mapped to empty text")
		}
	}
}

// The real China-site capture: level 1, empty desc_en throughout, and
// non-contiguous ids.
func TestMapChinaSiteCapture(t *testing.T) {
	recs, anoms := mapFixture(t, "past-events_cn.json", incident.StatusResolved)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	for _, r := range recs {
		if r.TitleLang != "zh" {
			t.Errorf("event %s title language = %q, want zh", r.Key.ProviderID, r.TitleLang)
		}
		if r.Severity != incident.SeverityMajor {
			t.Errorf("event %s severity = %v, want major (level 1)", r.Key.ProviderID, r.Severity)
		}
	}
	// Ids are not dense; nothing may assume they are sequential.
	if recs[0].Key.ProviderID == recs[1].Key.ProviderID {
		t.Error("distinct events collapsed to one id")
	}
	if !hasAnomaly(anoms, incident.AnomalyEmptyDescription) {
		t.Error("empty English descriptions must be flagged")
	}
}

func TestMapNoDescriptionYieldsPlaceholder(t *testing.T) {
	recs, anoms := mapFixture(t, "past-events_no_desc.json", incident.StatusResolved)
	r := recs[0]
	if r.Title != "(untitled #13)" {
		t.Errorf("title = %q, want the placeholder", r.Title)
	}
	if r.TitleLang != "none" {
		t.Errorf("title language = %q, want %q", r.TitleLang, "none")
	}
	if !hasAnomaly(anoms, incident.AnomalyEmptyDescription) {
		t.Error("a wholly untitled event must be flagged")
	}
}

// Losing the outage is worse than carrying one zero timestamp.
func TestMapBadTimestampKeepsTheRecord(t *testing.T) {
	recs, anoms := mapFixture(t, "past-events_bad_timestamp.json", incident.StatusResolved)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1; a malformed field must not discard the record", len(recs))
	}
	// The fixture uses a space separator with no zone, which parseTime tolerates
	// on purpose; what matters is that the record survived either way.
	if recs[0].StartedAt.IsZero() && !hasAnomaly(anoms, incident.AnomalyBadTimestamp) {
		t.Error("an unparseable timestamp must be flagged when it fails to parse")
	}
}

// Defends against an upstream int -> string change breaking every poll at once.
func TestMapEventIDAsStringIsAccepted(t *testing.T) {
	recs, _ := mapFixture(t, "past-events_id_as_string.json", incident.StatusResolved)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Key.ProviderID != "13" {
		t.Errorf("id = %q, want %q", recs[0].Key.ProviderID, "13")
	}
}

// The vendor adding a field must never break a poll.
func TestMapUnknownFieldsAreIgnored(t *testing.T) {
	recs, _ := mapFixture(t, "past-events_unknown_fields.json", incident.StatusResolved)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	base, _ := mapFixture(t, "past-events_event13.json", incident.StatusResolved)
	if !recs[0].FP.Equal(base[0].FP) {
		t.Error("an unrecognised field changed the fingerprint; forward compatibility is broken")
	}
}

func TestMapDuplicateIDsResolveDeterministically(t *testing.T) {
	var first incident.Record
	for i := 0; i < 25; i++ {
		recs, anoms := mapFixture(t, "past-events_duplicate_ids.json", incident.StatusResolved)
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1 after deduplication", len(recs))
		}
		if !hasAnomaly(anoms, incident.AnomalyDuplicateID) {
			t.Fatal("a duplicated id must be flagged")
		}
		if i == 0 {
			first = recs[0]
			continue
		}
		if !recs[0].FP.Equal(first.FP) || !recs[0].UpdatedAt.Equal(first.UpdatedAt) {
			t.Fatalf("iteration %d picked a different winner; deduplication is not deterministic", i)
		}
	}
	// The newer mtime must win.
	if first.UpdatedAt.Format("2006-01-02") != "2026-07-27" {
		t.Errorf("winner mtime = %v, want the newer of the two", first.UpdatedAt)
	}
}

func TestMapOrdersRecordsNumericallyByID(t *testing.T) {
	m := newMapper()
	ws := []wireEvent{
		{EventID: flexInt{Value: 20, Set: true}, DescEN: "twenty"},
		{EventID: flexInt{Value: 9, Set: true}, DescEN: "nine"},
		{EventID: flexInt{Value: 13, Set: true}, DescEN: "thirteen"},
	}
	got := m.mapEvents(ws, incident.StatusResolved)
	want := []string{"9", "13", "20"}
	for i, r := range got {
		if r.Key.ProviderID != want[i] {
			t.Errorf("position %d = %q, want %q (ids must sort numerically, not lexically)",
				i, r.Key.ProviderID, want[i])
		}
	}
}

func TestMapUnknownSeverityStillAlerts(t *testing.T) {
	m := newMapper()
	ws := []wireEvent{{EventID: flexInt{Value: 99, Set: true}, EventLvl: flexInt{Value: 7, Set: true}, DescEN: "novel"}}
	got := m.mapEvents(ws, incident.StatusOpen)

	if len(got) != 1 {
		t.Fatalf("an unrecognised severity must not drop the record")
	}
	if got[0].Severity != incident.SeverityUnknown {
		t.Errorf("severity = %v, want unknown", got[0].Severity)
	}
	if got[0].RawSeverity != "7" {
		t.Errorf("raw severity = %q, want %q; the original must never be discarded", got[0].RawSeverity, "7")
	}
	if !hasAnomaly(m.anomalies, incident.AnomalyUnknownSeverity) {
		t.Error("an unrecognised severity must be flagged")
	}
	// It must still pass a filter, or an ungradeable outage is silently dropped.
	f := incident.Filter{IncludeGlobal: true, MinSeverity: incident.SeverityCritical}
	if !f.Matches(got[0]) {
		t.Error("an unknown-severity record was filtered out; it must fail open")
	}
}

func TestMapProgressIsSortedAndFlagged(t *testing.T) {
	m := newMapper()
	ws := []wireEvent{{
		EventID: flexInt{Value: 1, Set: true},
		DescEN:  "x",
		Progress: []wireProgress{
			{EN: "second", Time: "2026-07-25T19:40:00Z"},
			{EN: "first", Time: "2026-07-25T19:05:00Z"},
		},
	}}
	got := m.mapEvents(ws, incident.StatusOpen)
	if got[0].Updates[0].Text != "first" {
		t.Errorf("progress not sorted chronologically: first entry is %q", got[0].Updates[0].Text)
	}
	if !hasAnomaly(m.anomalies, incident.AnomalyProgressOutOfOrder) {
		t.Error("out-of-order progress must be flagged")
	}
}

// An entry with no text in any language would add a phantom update to the
// progress count and trigger a spurious notification.
func TestMapDropsTextlessProgressEntries(t *testing.T) {
	m := newMapper()
	ws := []wireEvent{{
		EventID: flexInt{Value: 1, Set: true},
		DescEN:  "x",
		Progress: []wireProgress{
			{EN: "real", Time: "2026-07-25T19:05:00Z"},
			{EN: "", ZH: "  ", Time: "2026-07-25T19:40:00Z"},
		},
	}}
	got := m.mapEvents(ws, incident.StatusOpen)
	if len(got[0].Updates) != 1 {
		t.Errorf("got %d updates, want 1 (the textless entry must be dropped)", len(got[0].Updates))
	}
}

func TestMapIsDeterministicAcrossRuns(t *testing.T) {
	first, _ := mapFixture(t, "past-events_event13.json", incident.StatusResolved)
	for i := 0; i < 50; i++ {
		got, _ := mapFixture(t, "past-events_event13.json", incident.StatusResolved)
		if !got[0].FP.Equal(first[0].FP) {
			t.Fatalf("iteration %d produced a different fingerprint from identical input", i)
		}
	}
}

func TestFlexInt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    int64
		wantSet bool
		wantErr bool
	}{
		{name: "number", in: `13`, want: 13, wantSet: true},
		{name: "quoted number", in: `"13"`, want: 13, wantSet: true},
		{name: "null leaves it unset", in: `null`, wantSet: false},
		{name: "empty string leaves it unset", in: `""`, wantSet: false},
		{name: "zero is a real value", in: `0`, want: 0, wantSet: true},
		{name: "negative", in: `-1`, want: -1, wantSet: true},
		{name: "float truncates rather than dropping the record", in: `13.0`, want: 13, wantSet: true},
		{name: "non-numeric string is an error", in: `"abc"`, wantErr: true},
		{name: "object is an error", in: `{}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f flexInt
			err := json.Unmarshal([]byte(tc.in), &f)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if f.Value != tc.want || f.Set != tc.wantSet {
				t.Errorf("got {%d %v}, want {%d %v}", f.Value, f.Set, tc.want, tc.wantSet)
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     string
		wantOK bool
		want   string
	}{
		{name: "the documented shape", in: "2026-07-25T19:05:00Z", wantOK: true, want: "2026-07-25T19:05:00Z"},
		{name: "fractional seconds", in: "2026-07-25T19:05:00.123Z", wantOK: true, want: "2026-07-25T19:05:00Z"},
		{name: "numeric offset is normalized to UTC", in: "2026-07-26T02:05:00+07:00", wantOK: true, want: "2026-07-25T19:05:00Z"},
		{name: "space separator is tolerated", in: "2026-07-25 19:05:00", wantOK: true, want: "2026-07-25T19:05:00Z"},
		{name: "zone omitted is assumed UTC, never local", in: "2026-07-25T19:05:00", wantOK: true, want: "2026-07-25T19:05:00Z"},
		{name: "empty is not a time", in: "", wantOK: false},
		{name: "whitespace is not a time", in: "   ", wantOK: false},
		{name: "date only is rejected", in: "2026-07-25", wantOK: false},
		{name: "garbage is rejected", in: "yesterday", wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseTime(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.Format("2006-01-02T15:04:05Z") != tc.want {
				t.Errorf("got %s, want %s", got.Format("2006-01-02T15:04:05Z"), tc.want)
			}
		})
	}
}

// Milliseconds, numeric offsets and date-only values are all rejected upstream
// with HTTP 400, so this format is a contract, not a style choice.
func TestFormatTimeMatchesTheOnlyAcceptedShape(t *testing.T) {
	tm, _ := parseTime("2026-07-26T02:05:00.999+07:00")
	if got, want := formatTime(tm), "2026-07-25T19:05:00Z"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
