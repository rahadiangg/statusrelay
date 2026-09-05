package incident

import "testing"

func jakartaOnly() Filter {
	return Filter{
		Regions:       map[string]bool{"ap-southeast-4": true},
		IncludeGlobal: true,
	}
}

func recWithRegions(codes ...string) Record {
	r := Record{Key: Key{SourceID: "huawei-intl", ProviderID: "13"}, Severity: SeverityCritical}
	for _, c := range codes {
		r.Scope = append(r.Scope, Scope{RegionCode: c, Services: []Service{{ID: "svc-ecs", Abbr: "ECS"}}})
	}
	return r
}

// The single most dangerous configuration error this service has: the
// neighbouring region code differs by one character, matches nothing, and
// produces no error at any layer — the watcher just monitors the wrong country
// forever while reporting healthy.
func TestFilterMatchesExactRegionCodeOnly(t *testing.T) {
	f := jakartaOnly()

	for _, tc := range []struct {
		name string
		code string
		want bool
	}{
		{name: "the watched region matches", code: "ap-southeast-4", want: true},
		{name: "the neighbouring region does not", code: "ap-southeast-3", want: false},
		{name: "a prefix of the watched region does not", code: "ap-southeast", want: false},
		{name: "the watched region as a prefix of something longer does not", code: "ap-southeast-40", want: false},
		{name: "an unrelated region does not", code: "cn-north-4", want: false},
		{name: "case differences do not match", code: "AP-SOUTHEAST-4", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.Matches(recWithRegions(tc.code)); got != tc.want {
				t.Errorf("Matches(%q) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}

func TestFilterMatchesWhenAnyScopeMatches(t *testing.T) {
	f := jakartaOnly()
	if !f.Matches(recWithRegions("ap-southeast-3", "tr-west-1", "ap-southeast-4")) {
		t.Error("a record listing the watched region among others must match")
	}
	if f.Matches(recWithRegions("ap-southeast-3", "tr-west-1")) {
		t.Error("a record listing only unwatched regions must not match")
	}
}

// A provider publishing a platform-wide event with no region attached is a real
// shape. Dropping it trades a once-a-year false positive for a missed total
// outage, so it is included by default.
func TestFilterGlobalIncident(t *testing.T) {
	for _, tc := range []struct {
		name          string
		includeGlobal bool
		global        bool
		scope         []Scope
		want          bool
	}{
		{name: "global flag included by default", includeGlobal: true, global: true, want: true},
		{name: "global flag excluded when configured off", includeGlobal: false, global: true, want: false},
		{name: "no scope at all is treated as global", includeGlobal: true, scope: nil, want: true},
		{name: "no scope excluded when global is off", includeGlobal: false, scope: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := Filter{Regions: map[string]bool{"ap-southeast-4": true}, IncludeGlobal: tc.includeGlobal}
			r := Record{Severity: SeverityCritical, Global: tc.global, Scope: tc.scope}
			if got := f.Matches(r); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilterServices(t *testing.T) {
	f := Filter{
		Regions:  map[string]bool{"ap-southeast-4": true},
		Services: map[string]bool{"ECS": true},
	}
	r := recWithRegions("ap-southeast-4")

	if !f.Matches(r) {
		t.Error("a watched service in a watched region must match")
	}

	r.Scope[0].Services = []Service{{ID: "svc-dds", Abbr: "DDS"}}
	if f.Matches(r) {
		t.Error("an unwatched service in a watched region must not match")
	}

	// The service filter must not leak across regions: ECS in Singapore is not
	// ECS in Jakarta.
	r2 := recWithRegions("ap-southeast-3")
	if f.Matches(r2) {
		t.Error("a watched service in an unwatched region must not match")
	}
}

func TestFilterServiceAbbrIsCaseInsensitive(t *testing.T) {
	f := Filter{
		Regions:  map[string]bool{"ap-southeast-4": true},
		Services: map[string]bool{"ECS": true},
	}
	r := Record{Severity: SeverityCritical, Scope: []Scope{
		{RegionCode: "ap-southeast-4", Services: []Service{{ID: "svc-ecs", Abbr: "ecs"}}},
	}}
	if !f.Matches(r) {
		t.Error("service abbreviation matching must be case-insensitive")
	}
}

func TestFilterEmptyRegionsMatchesEverything(t *testing.T) {
	f := Filter{IncludeGlobal: true}
	if !f.Matches(recWithRegions("cn-north-4")) {
		t.Error("an empty region set must match every region")
	}
}

// An ungradeable incident is not a minor one. The severity domains upstream are
// undocumented and gain values without notice, so unknown always passes.
func TestFilterMinSeverity(t *testing.T) {
	for _, tc := range []struct {
		name string
		sev  Severity
		min  Severity
		want bool
	}{
		{name: "above the threshold passes", sev: SeverityCritical, min: SeverityMajor, want: true},
		{name: "at the threshold passes", sev: SeverityMajor, min: SeverityMajor, want: true},
		{name: "below the threshold is dropped", sev: SeverityMinor, min: SeverityMajor, want: false},
		{name: "unknown always passes regardless of threshold", sev: SeverityUnknown, min: SeverityCritical, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := Filter{IncludeGlobal: true, MinSeverity: tc.min}
			r := Record{Severity: tc.sev, Global: true}
			if got := f.Matches(r); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchedScopesNarrowsToWatchedRegions(t *testing.T) {
	f := jakartaOnly()
	r := recWithRegions("ap-southeast-3", "ap-southeast-4", "tr-west-1")

	got := f.MatchedScopes(r)
	if len(got) != 1 {
		t.Fatalf("got %d matched scopes, want 1", len(got))
	}
	if got[0].RegionCode != "ap-southeast-4" {
		t.Errorf("got region %q, want %q", got[0].RegionCode, "ap-southeast-4")
	}
}

func TestMatchedScopesReturnsAllWhenUnfiltered(t *testing.T) {
	f := Filter{IncludeGlobal: true}
	r := recWithRegions("ap-southeast-3", "ap-southeast-4")
	if got := len(f.MatchedScopes(r)); got != 2 {
		t.Errorf("got %d scopes, want 2", got)
	}
}
