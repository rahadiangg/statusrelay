// Package incident defines the contract every status-source provider implements,
// plus the normalized shapes the rest of the service speaks.
//
// Adapters live in subpackages (huawei, and whatever comes next). Nothing
// outside this package may depend on a concrete adapter: callers talk to Source,
// so a new status page is an added subpackage and one line in cmd/statusrelay, not
// an edit to the poll path.
//
// The shapes here are deliberately paranoid. The upstream this was designed
// against publishes no status field, no delta feed, and returns HTTP 200 with an
// empty array for five distinct failure conditions — including "you called a
// renamed endpoint" and "you are reading a different site's data". Almost every
// unusual-looking field below exists to keep one of those from being read as
// "everything is fine".
package incident

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Source is one configured status feed. Two instances of the same adapter
// (an international and a mainland endpoint, say) is a normal deployment, which
// is why ID and Kind are separate.
type Source interface {
	// ID is the instance name, e.g. "huawei-intl".
	ID() string
	// Kind is the adapter name, e.g. "huawei".
	Kind() string
	Capabilities() Capabilities

	// Fetch returns the provider's whole current view of the world. It never
	// returns a partial view dressed as a complete one: see Snapshot.Complete.
	Fetch(ctx context.Context) (*Snapshot, error)

	// SelfCheck proves the source is still telling the truth. It exists because
	// most of the ways this kind of API fails return HTTP 200 with a body that
	// is indistinguishable from "no incidents", so a successful fetch is not by
	// itself evidence of anything.
	SelfCheck(ctx context.Context) error
}

// Capabilities lets the poller pick strategies without type-asserting on a
// concrete adapter.
type Capabilities struct {
	// HasExplicitStatus is false for providers where resolution is inferred
	// from set membership rather than read from a field.
	HasExplicitStatus bool
	// HasUpdateTimestamp is false for providers that expose no record mtime, or
	// expose one only for part of the corpus.
	HasUpdateTimestamp bool
	// ResolutionIsStructural means "resolved" is derived from which list a
	// record appears in, not from its content.
	ResolutionIsStructural bool
	SupportsHistoryWindow  bool
	SupportsPostMortem     bool
	MaxHistoryLookback     time.Duration
}

// Snapshot is one provider's complete view at one instant.
type Snapshot struct {
	SourceID  string
	FetchedAt time.Time

	// Open holds records the provider asserts are currently unresolved.
	Open []Record
	// Recent holds records the provider asserts are resolved and vouches for.
	Recent []Record

	// Complete reports whether absence is meaningful.
	//
	// When false, a record missing from Open is NOT evidence that it resolved:
	// it is equally consistent with a half-failed fetch, a silently ignored
	// query parameter, or the endpoint having been renamed. The poller refuses
	// to infer resolution from a snapshot that is not Complete.
	//
	// This is the single most dangerous bug this service can have — reporting
	// "all clear" during an outage — so it is a field on the wire type rather
	// than a convention.
	Complete bool

	// UnresolvedCount is the provider's own count, obtained from a different
	// endpoint than Open, used purely as a cross-check. -1 when unavailable.
	UnresolvedCount int

	// Warnings are non-fatal anomalies worth a metric but not worth failing on.
	Warnings []Warning

	// Mirror is true when this snapshot was served by the adapter's fallback
	// host rather than its primary. The data is meant to be identical, but a
	// primary that is silently blocked for weeks is worth a gauge: it is the
	// first sign the adapter is one outage away from blind.
	Mirror bool
}

// Warning is a typed anomaly. Kind is a low-cardinality label, safe for metrics.
type Warning struct {
	Kind   string
	Detail string
}

// Anomaly kinds. These are metric label values, so the set is closed and each
// value is stable across releases.
const (
	AnomalyEmptyDescription   = "empty_description"
	AnomalyNullScope          = "null_scope"
	AnomalyDuplicateID        = "duplicate_id"
	AnomalyIDReuse            = "id_reuse"
	AnomalyProgressShrank     = "progress_shrank"
	AnomalyProgressOutOfOrder = "progress_out_of_order"
	AnomalyFutureTimestamp    = "future_timestamp"
	AnomalyBadTimestamp       = "bad_timestamp"
	AnomalyUnknownSeverity    = "unknown_severity"
	AnomalySilentMtimeBump    = "silent_mtime_bump"
	AnomalyCountMismatch      = "count_mismatch"
	// AnomalyStatusConflict means the list a record appeared in disagrees with
	// the record's own status field (an "open" row with an end time, or a
	// "resolved" row without one). Membership decides; the field is only a
	// witness, and this is how its testimony is heard.
	AnomalyStatusConflict = "status_conflict"
	AnomalyUnknownStatus  = "unknown_status"
)

// Region is one region in a provider's inventory.
//
// The inventory says what EXISTS, not what is working: these providers publish
// no per-service health, and their own green-tick grids are a client-side
// projection of published incidents onto this list. Nothing downstream may
// derive a health signal from a Region.
type Region struct {
	Code string
	Name string
}

// Key identifies a record globally.
//
// ProviderID is a string even where the upstream uses an integer: this upstream
// numbers events 13, 17, 20 today, and the next provider will use a UUID.
// Widening an int later is a migration; starting with a string is free.
type Key struct {
	SourceID   string
	ProviderID string
}

func (k Key) String() string { return k.SourceID + "/" + k.ProviderID }

// Severity is the normalized severity ladder.
//
// SeverityUnknown is not an error state and is never dropped. Providers publish
// undocumented severity domains that gain values without notice, so an
// unrecognised level has to fail open — alerting on something we cannot grade is
// correct; silently discarding an outage because its level was novel is not.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityMinor
	SeverityMajor
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityMinor:
		return "minor"
	case SeverityMajor:
		return "major"
	case SeverityCritical:
		return "critical"
	case SeverityUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// ParseSeverity maps a configured name to a Severity. Unrecognised names return
// false so config validation can reject them at load time rather than silently
// grading every incident as unknown.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "info":
		return SeverityInfo, true
	case "minor":
		return SeverityMinor, true
	case "major":
		return SeverityMajor, true
	case "critical":
		return SeverityCritical, true
	case "unknown":
		return SeverityUnknown, true
	default:
		return SeverityUnknown, false
	}
}

// Status is where a record sits in its lifecycle.
type Status int

const (
	// StatusOpen means the provider currently lists the record as unresolved.
	StatusOpen Status = iota
	// StatusResolved means the provider vouches that it is over.
	StatusResolved
	// StatusUnknown means the record disappeared from both lists without ever
	// being reported resolved. It is NOT resolved: it keeps alerting until the
	// provider says otherwise or the vanish grace period expires.
	StatusUnknown
)

func (s Status) String() string {
	switch s {
	case StatusOpen:
		return "open"
	case StatusResolved:
		return "resolved"
	case StatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// Service is one affected product within a region.
type Service struct {
	ID   string
	Name string
	Abbr string
}

// Scope is one affected region and the services named within it.
//
// Services may be empty: a provider can name a region without enumerating what
// broke inside it.
type Scope struct {
	RegionID   string
	RegionCode string
	RegionName string
	Services   []Service
}

// Update is one progress entry on a record. Providers append these; they are
// never edited in place, and a shrinking list is treated as a provider bug
// rather than as new information.
type Update struct {
	At   time.Time
	Text string
	Lang string
	Hash string
}

// Record is one normalized incident.
type Record struct {
	Key Key

	// Title is the best available human title: the preferred language, falling
	// back to any other the provider published. Some upstreams ship records
	// whose English description is an empty string, so a naive reader produces
	// blank alerts.
	Title string
	// TitleLang records which fallback fired ("en", "zh", "none"), so a sudden
	// shift to a fallback is visible rather than merely odd-looking.
	TitleLang string
	// Titles keeps every localized string the provider published, losslessly.
	Titles map[string]string

	Severity Severity
	// RawSeverity is the provider's own value, kept verbatim. The normalized
	// ladder is lossy by design; this is what you look at when a new level
	// appears and nobody knows what it means.
	RawSeverity string

	Status Status

	// StartedAt is when the provider PUBLISHED the record, which is not when
	// the fault began. On the one incident this was designed against, detection
	// preceded publication by roughly sixteen minutes. The field is named
	// StartedAt rather than OccurredAt to keep that distinction visible at the
	// call site.
	StartedAt time.Time
	// UpdatedAt is the provider's record mtime, or the zero time when the
	// provider cannot attest to one. Never treat zero as "never updated".
	UpdatedAt time.Time
	EndedAt   time.Time

	// Global is true when the provider published no region at all.
	//
	// A region-less event is a real shape, not a parse failure. Encoding it as
	// an empty Scope slice loses that distinction, and the first person to
	// write len(Scope) == 0 would silently drop platform-wide outages.
	Global bool

	Scope   []Scope
	Updates []Update

	// URL is the provider's public page for this record, or the status site
	// root when the provider has no per-incident page. Empty only for events
	// that have no upstream at all (statusrelay's own health transitions).
	// It is for humans and never fetched; providers may change the pattern
	// and a stale link is an inconvenience, not a false alarm.
	URL string

	HasReport bool
	// RawReport is opaque on purpose. On the upstream this was built against no
	// record has ever carried a report, so its shape has never been observed;
	// any struct invented now would silently drop fields the day a real one
	// appears.
	RawReport json.RawMessage

	FP Fingerprint
}

// PreferredTitle picks the title for a given language preference, falling back
// through every other language the provider published. It returns the chosen
// text and the language tag it came from, so callers can record which path
// fired.
//
// The fallback order is the sorted remainder rather than map order: Go
// randomizes map iteration, and a title that changed between two polls of
// identical data would be indistinguishable from a real incident update.
func PreferredTitle(titles map[string]string, prefer, providerID string) (text, lang string) {
	if t := strings.TrimSpace(titles[prefer]); t != "" {
		return t, prefer
	}
	langs := make([]string, 0, len(titles))
	for l := range titles {
		if l != prefer {
			langs = append(langs, l)
		}
	}
	sort.Strings(langs)
	for _, l := range langs {
		if t := strings.TrimSpace(titles[l]); t != "" {
			return t, l
		}
	}
	// Never return an empty title: a blank alert is worse than an ugly one,
	// because it reads as a rendering bug rather than as a real outage.
	return "(untitled #" + providerID + ")", "none"
}
