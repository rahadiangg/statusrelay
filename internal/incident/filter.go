package incident

import "strings"

// Filter decides which records this deployment cares about.
//
// Filtering is applied when deciding what to NOTIFY, never when deciding what to
// STORE. Storing only matched records would make "a watched region was added to
// an incident we had been ignoring" indistinguishable from "a brand new
// incident", and would make the reverse transition impossible to detect at all.
type Filter struct {
	// Regions is the set of region codes to watch. Empty means every region,
	// but callers must not construct that state by accident: config rejects an
	// empty region list unless watching everything was requested explicitly,
	// because "empty means all" is how people end up believing they filtered.
	Regions map[string]bool

	// Services optionally narrows to specific service abbreviations. Empty
	// means every service in a matched region.
	Services map[string]bool

	// IncludeGlobal controls whether records with no region at all match.
	//
	// Default true. A provider publishing a platform-wide event with no region
	// attached is a real shape, and dropping it to avoid a false positive trades
	// a once-a-year annoyance for a missed total outage.
	IncludeGlobal bool

	// MinSeverity drops records graded below this level. SeverityUnknown always
	// passes regardless of this setting: an ungradeable incident is not a minor
	// one, and the severity domains here are undocumented.
	MinSeverity Severity
}

// Matches reports whether a record is one this deployment wants to hear about.
func (f Filter) Matches(r Record) bool {
	if !f.severityMatches(r.Severity) {
		return false
	}
	if r.Global || len(r.Scope) == 0 {
		return f.IncludeGlobal
	}
	if len(f.Regions) == 0 && len(f.Services) == 0 {
		return true
	}
	for _, sc := range r.Scope {
		if !f.regionMatches(sc.RegionCode) {
			continue
		}
		if len(f.Services) == 0 {
			return true
		}
		for _, sv := range sc.Services {
			if f.Services[strings.ToUpper(sv.Abbr)] {
				return true
			}
		}
	}
	return false
}

// MatchedScopes returns only the scopes this deployment watches, so an alert
// can lead with "your regions" rather than reprinting every region the provider
// listed.
func (f Filter) MatchedScopes(r Record) []Scope {
	if len(f.Regions) == 0 {
		return r.Scope
	}
	out := make([]Scope, 0, len(r.Scope))
	for _, sc := range r.Scope {
		if f.regionMatches(sc.RegionCode) {
			out = append(out, sc)
		}
	}
	return out
}

// regionMatches compares region codes exactly.
//
// Exactly, and never by prefix: neighbouring regions in these code spaces differ
// by a single trailing character, so a prefix or substring match silently
// watches the wrong country and never reports an error.
func (f Filter) regionMatches(code string) bool {
	if len(f.Regions) == 0 {
		return true
	}
	return f.Regions[code]
}

func (f Filter) severityMatches(s Severity) bool {
	if s == SeverityUnknown {
		return true
	}
	return s >= f.MinSeverity
}
