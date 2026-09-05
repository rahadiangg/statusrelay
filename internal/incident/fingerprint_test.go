package incident

import (
	"testing"
	"time"
)

func tm(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// baseRecord is the reference incident: multi-region, multi-service, with
// progress entries. Tests mutate a copy to prove exactly one thing changes.
func baseRecord() Record {
	return Record{
		Key:         Key{SourceID: "huawei-intl", ProviderID: "13"},
		Titles:      map[string]string{"en": "Account anomaly", "zh": "账号异常"},
		Title:       "Account anomaly",
		TitleLang:   "en",
		Severity:    SeverityCritical,
		RawSeverity: "2",
		Status:      StatusOpen,
		StartedAt:   tm("2026-07-25T19:05:00Z"),
		UpdatedAt:   tm("2026-07-27T00:04:52Z"),
		Scope: []Scope{
			{RegionCode: "ap-southeast-4", RegionName: "AP-Jakarta", Services: []Service{
				{ID: "svc-ecs", Abbr: "ECS"}, {ID: "svc-iam", Abbr: "IAM"},
			}},
			{RegionCode: "ap-southeast-3", RegionName: "AP-Singapore", Services: []Service{
				{ID: "svc-ecs", Abbr: "ECS"},
			}},
		},
		Updates: []Update{
			{At: tm("2026-07-25T19:05:00Z"), Text: "We are investigating."},
			{At: tm("2026-07-25T19:40:00Z"), Text: "Engineers are working on it."},
		},
	}
}

func TestFingerprintStableAcrossScopeOrdering(t *testing.T) {
	a := baseRecord()
	b := baseRecord()
	b.Scope[0], b.Scope[1] = b.Scope[1], b.Scope[0]

	if got, want := Compute(b).Scope, Compute(a).Scope; got != want {
		t.Errorf("reordering regions changed the scope hash\ngot  %s\nwant %s", got, want)
	}
}

func TestFingerprintStableAcrossServiceOrdering(t *testing.T) {
	a := baseRecord()
	b := baseRecord()
	b.Scope[0].Services[0], b.Scope[0].Services[1] = b.Scope[0].Services[1], b.Scope[0].Services[0]

	if got, want := Compute(b).Scope, Compute(a).Scope; got != want {
		t.Errorf("reordering services changed the scope hash\ngot  %s\nwant %s", got, want)
	}
}

// Go randomizes map iteration order. A title hash that depended on it would
// differ between two polls of identical data and look like an incident update.
func TestFingerprintStableAcrossMapIteration(t *testing.T) {
	want := Compute(baseRecord()).Content
	for i := 0; i < 100; i++ {
		if got := Compute(baseRecord()).Content; got != want {
			t.Fatalf("iteration %d: content hash unstable\ngot  %s\nwant %s", i, got, want)
		}
	}
}

// Upstreams mix "Z" and numeric offsets for the same instant. A zone-format
// change must not read as a change.
func TestFingerprintNormalizesTimezone(t *testing.T) {
	a := baseRecord()
	b := baseRecord()
	jakarta := time.FixedZone("WIB", 7*3600)
	b.StartedAt = a.StartedAt.In(jakarta)
	b.Updates[0].At = a.Updates[0].At.In(jakarta)

	if got, want := Compute(b).Content, Compute(a).Content; got != want {
		t.Errorf("timezone representation changed the content hash")
	}
	if got, want := Compute(b).Progress, Compute(a).Progress; got != want {
		t.Errorf("timezone representation changed the progress hash")
	}
}

// The mtime is a separate signal so that an mtime-only bump is detectable and
// deliberately non-alerting. Folding it into a hash would make every silent
// record touch look like a content change.
func TestFingerprintExcludesMtime(t *testing.T) {
	a := baseRecord()
	b := baseRecord()
	b.UpdatedAt = a.UpdatedAt.Add(35 * time.Minute)

	fa, fb := Compute(a), Compute(b)
	if !fa.Equal(fb) {
		t.Error("an mtime-only change altered a hash; it must not")
	}
	if fa.Mtime.Equal(fb.Mtime) {
		t.Error("Mtime was not carried through, so the bump is undetectable")
	}
}

func TestFingerprintNilAndEmptyScopeEqual(t *testing.T) {
	a := baseRecord()
	a.Scope = nil
	b := baseRecord()
	b.Scope = []Scope{}

	if got, want := Compute(b).Scope, Compute(a).Scope; got != want {
		t.Errorf("nil and empty scope hashed differently")
	}
}

// Global is folded into the scope hash so that a record losing its last region
// is a scope change rather than hashing identically to one that never had any.
func TestFingerprintGlobalIsPartOfScope(t *testing.T) {
	a := baseRecord()
	a.Scope = nil
	b := a
	b.Global = true

	if Compute(a).Scope == Compute(b).Scope {
		t.Error("Global did not affect the scope hash")
	}
}

func TestFingerprintChangesOnEachDimension(t *testing.T) {
	base := Compute(baseRecord())

	for _, tc := range []struct {
		name         string
		mutate       func(*Record)
		wantContent  bool
		wantScope    bool
		wantProgress bool
	}{
		{
			name:        "title edit is a content change only",
			mutate:      func(r *Record) { r.Titles["en"] = "Account anomaly (updated)" },
			wantContent: true,
		},
		{
			name:        "severity change is a content change only",
			mutate:      func(r *Record) { r.Severity = SeverityMajor },
			wantContent: true,
		},
		{
			name:        "status change is a content change only",
			mutate:      func(r *Record) { r.Status = StatusResolved },
			wantContent: true,
		},
		{
			name:      "adding a region is a scope change only",
			mutate:    func(r *Record) { r.Scope = append(r.Scope, Scope{RegionCode: "tr-west-1"}) },
			wantScope: true,
		},
		{
			name: "adding a service is a scope change only",
			mutate: func(r *Record) {
				r.Scope[0].Services = append(r.Scope[0].Services, Service{ID: "svc-elb", Abbr: "ELB"})
			},
			wantScope: true,
		},
		{
			name: "appending progress is a progress change only",
			mutate: func(r *Record) {
				r.Updates = append(r.Updates, Update{At: tm("2026-07-25T20:30:00Z"), Text: "Recovered."})
			},
			wantProgress: true,
		},
		{
			name:         "editing existing progress text is a progress change",
			mutate:       func(r *Record) { r.Updates[0].Text = "We are still investigating." },
			wantProgress: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := baseRecord()
			tc.mutate(&r)
			got := Compute(r)

			if changed := got.Content != base.Content; changed != tc.wantContent {
				t.Errorf("content changed = %v, want %v", changed, tc.wantContent)
			}
			if changed := got.Scope != base.Scope; changed != tc.wantScope {
				t.Errorf("scope changed = %v, want %v", changed, tc.wantScope)
			}
			if changed := got.Progress != base.Progress; changed != tc.wantProgress {
				t.Errorf("progress changed = %v, want %v", changed, tc.wantProgress)
			}
		})
	}
}

// Without length-prefixing, {"ab","c"} and {"a","bc"} hash identically, so a
// service id shifting a character between fields would be invisible.
func TestFingerprintFieldsAreUnambiguous(t *testing.T) {
	a := baseRecord()
	a.Scope = []Scope{{RegionCode: "ab", Services: []Service{{ID: "c"}}}}
	b := baseRecord()
	b.Scope = []Scope{{RegionCode: "a", Services: []Service{{ID: "bc"}}}}

	if Compute(a).Scope == Compute(b).Scope {
		t.Error("ambiguous concatenation: distinct scopes hashed identically")
	}
}

// The zero time must be distinguishable from a real timestamp, so that "the
// provider supplied nothing" is not silently equal to some default instant.
func TestFingerprintZeroTimeIsDistinct(t *testing.T) {
	a := baseRecord()
	a.EndedAt = time.Time{}
	b := baseRecord()
	b.EndedAt = tm("0001-01-01T00:00:01Z")

	if Compute(a).Content == Compute(b).Content {
		t.Error("zero time hashed the same as a real timestamp")
	}
}

func TestSortUpdates(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          []Update
		wantOrdered bool
		wantFirst   string
	}{
		{
			name: "already ordered",
			in: []Update{
				{At: tm("2026-07-25T19:05:00Z"), Text: "first"},
				{At: tm("2026-07-25T19:40:00Z"), Text: "second"},
			},
			wantOrdered: true,
			wantFirst:   "first",
		},
		{
			name: "out of order is sorted and reported",
			in: []Update{
				{At: tm("2026-07-25T19:40:00Z"), Text: "second"},
				{At: tm("2026-07-25T19:05:00Z"), Text: "first"},
			},
			wantOrdered: false,
			wantFirst:   "first",
		},
		{
			// Second-precision timestamps mean two entries can share an
			// instant; payload order is the only remaining signal, so the sort
			// must be stable.
			name: "equal timestamps keep payload order",
			in: []Update{
				{At: tm("2026-07-25T19:05:00Z"), Text: "alpha"},
				{At: tm("2026-07-25T19:05:00Z"), Text: "beta"},
			},
			wantOrdered: true,
			wantFirst:   "alpha",
		},
		{name: "empty", in: nil, wantOrdered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ordered := SortUpdates(tc.in)
			if ordered != tc.wantOrdered {
				t.Errorf("wasOrdered = %v, want %v", ordered, tc.wantOrdered)
			}
			if tc.wantFirst != "" && got[0].Text != tc.wantFirst {
				t.Errorf("first entry = %q, want %q", got[0].Text, tc.wantFirst)
			}
			if len(tc.in) > 0 && &got[0] == &tc.in[0] {
				t.Error("SortUpdates mutated its input slice")
			}
		})
	}
}

func TestHashUpdateTextDistinguishesEntries(t *testing.T) {
	at := tm("2026-07-25T19:05:00Z")
	same := HashUpdateText(at, "We are investigating.")
	if same != HashUpdateText(at, "We are investigating.") {
		t.Error("hash is not deterministic")
	}
	if same == HashUpdateText(at, "We are still investigating.") {
		t.Error("different text hashed identically")
	}
	if same == HashUpdateText(at.Add(time.Minute), "We are investigating.") {
		t.Error("different timestamp hashed identically")
	}
}
