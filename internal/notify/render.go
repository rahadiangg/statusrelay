package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// Message is the rendered, transport-neutral text of one event.
//
// It is plain text on purpose. Incident bodies are multi-paragraph, frequently
// CJK, and contain '<', '*', '_' and backticks as ordinary punctuation; any
// markup mode would need escaping in three transports and would break silently
// the first time a provider used a character nobody thought of.
type Message struct {
	// Subject is a single line: no CR, no LF. Safe as an email Subject or a
	// chat title.
	Subject string
	Body    string
}

const timeLayout = "2006-01-02 15:04 MST"

// maxSubjectRegions caps the region list in a subject: past this the line is
// no longer scannable and the body has the full list anyway.
const maxSubjectRegions = 3

// kindLabels are the human words for each transition. Vanished is spelled out
// because a reader skimming a subject line must not mistake it for resolved.
var kindLabels = map[incident.EventKind]string{
	incident.KindNew:                 "NEW",
	incident.KindUpdated:             "UPDATED",
	incident.KindScopeChanged:        "SCOPE CHANGED",
	incident.KindMinorUpdated:        "MINOR UPDATE",
	incident.KindResolved:            "RESOLVED",
	incident.KindResolvedInferred:    "RESOLVED (inferred, provider never confirmed)",
	incident.KindReopened:            "REOPENED",
	incident.KindMissedAndResolved:   "OPENED AND RESOLVED between polls",
	incident.KindUpdatedAfterResolve: "POST-MORTEM UPDATE",
	incident.KindVanished:            "VANISHED (not resolved)",
	incident.KindScopeExited:         "LEFT WATCHED SCOPE",
	KindSourceBlind:                  "SOURCE BLIND",
	KindSourceRecovered:              "SOURCE RECOVERED",
}

// Renderer turns events into messages. The zero value renders in UTC with raw
// source ids, which is what every test and every v0.1 deployment gets.
type Renderer struct {
	// Loc is the zone timestamps are printed in. nil means UTC.
	Loc *time.Location
	// Names maps a source id to the name a human calls it ("Huawei Cloud").
	// A missing entry falls back to the id.
	Names map[string]string
}

// Render produces the message for one event with the zero Renderer.
func Render(ev incident.Event) Message { return Renderer{}.Render(ev) }

// Render produces the message for one event.
//
// Only NewUpdates are quoted, never the full history: an incident with thirty
// progress entries would otherwise resend all thirty on every change.
func (rd Renderer) Render(ev incident.Event) Message {
	r := ev.Record
	label := kindLabels[ev.Kind]
	if label == "" {
		// An unknown kind is a programming error upstream, but a blank label
		// would hide it; the raw kind at least shows what happened.
		label = strings.ToUpper(string(ev.Kind))
	}
	sev := severityLabel(r)
	provider := rd.name(r.Key.SourceID)
	health := r.Key.ProviderID == healthProviderID

	// "Huawei Cloud (huawei-intl #13)" when a display name is configured,
	// "huawei-intl #13" when it is not; the id is never printed twice.
	who := r.Key.SourceID
	if !health {
		who += " #" + r.Key.ProviderID
	}
	if provider != r.Key.SourceID {
		who = provider + " (" + who + ")"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s · %s · %s\n", label, sev, who)
	fmt.Fprintf(&b, "%s\n", r.Title)
	if r.URL != "" {
		fmt.Fprintf(&b, "Details: %s\n", oneLine(r.URL))
	}
	fmt.Fprintf(&b, "Status: %s\n", r.Status)
	if !r.StartedAt.IsZero() {
		fmt.Fprintf(&b, "Published: %s\n", rd.fmtTime(r.StartedAt))
	}
	if !r.EndedAt.IsZero() {
		fmt.Fprintf(&b, "Ended: %s\n", rd.fmtTime(r.EndedAt))
	}
	// Two region lines, because they answer different questions: "is it
	// mine?" and "how big is it?". They collapse to one when identical so a
	// deployment watching every region is not told everything twice.
	if !health {
		watched, all := regions(watchedScope(ev), r), regions(r.Scope, r)
		if !r.Global && watched != all {
			fmt.Fprintf(&b, "Watched: %s\n", watched)
		}
		fmt.Fprintf(&b, "All regions: %s\n", all)
	}
	if len(ev.Added) > 0 {
		fmt.Fprintf(&b, "Now affecting: %s\n", strings.Join(ev.Added, ", "))
	}
	if len(ev.Removed) > 0 {
		fmt.Fprintf(&b, "No longer affecting: %s\n", strings.Join(ev.Removed, ", "))
	}
	for _, u := range ev.NewUpdates {
		b.WriteString("\n")
		if u.At.IsZero() {
			b.WriteString("Update:\n")
		} else {
			fmt.Fprintf(&b, "Update %s:\n", rd.fmtTime(u.At))
		}
		b.WriteString(indent(u.Text))
		b.WriteString("\n")
	}
	if ev.Kind == incident.KindVanished {
		b.WriteString("\nThe provider stopped listing this incident without marking it resolved. Treat it as still open until confirmed.\n")
	}
	if ev.Kind == KindSourceBlind {
		b.WriteString("\nUntil this recovers, \"no incidents\" means nothing: the feed is not being read. Check the provider site by hand.\n")
	}
	if ev.ColdStart {
		b.WriteString("\nFirst run: this may have started before statusrelay did.\n")
	}

	// The subject names the transition, the provider and OUR regions, never
	// the provider's title: those run to 150 characters listing every region
	// on earth, and the one thing a pager must answer at a glance is
	// "is this mine?".
	subject := fmt.Sprintf("[statusrelay] %s %s · %s", label, sev, provider)
	if !health {
		subject += " · " + subjectRegions(ev)
	}
	return Message{
		Subject: oneLine(subject),
		Body:    strings.TrimRight(b.String(), "\n") + "\n",
	}
}

func (rd Renderer) name(sourceID string) string {
	if n, ok := rd.Names[sourceID]; ok && n != "" {
		return n
	}
	return sourceID
}

func (rd Renderer) fmtTime(t time.Time) string {
	loc := rd.Loc
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format(timeLayout)
}

// severityLabel shows the raw provider value beside an unknown grade, so the
// day a new level appears the alert says what it was rather than just
// "unknown".
func severityLabel(r incident.Record) string {
	if r.Severity == incident.SeverityUnknown && r.RawSeverity != "" {
		return fmt.Sprintf("unknown (level %s)", r.RawSeverity)
	}
	return r.Severity.String()
}

// watchedScope is the filtered scope when the event carries one, else the
// full scope: an event built without a filter has nothing narrower to show.
func watchedScope(ev incident.Event) []incident.Scope {
	if ev.Watched != nil {
		return ev.Watched
	}
	return ev.Record.Scope
}

// regions renders a scope list. A global record and a record with an empty
// scope are different shapes and must read differently: the first is a
// platform-wide event, the second is the provider naming nothing.
func regions(scope []incident.Scope, r incident.Record) string {
	if r.Global {
		return "global (no region published)"
	}
	if len(scope) == 0 {
		return "none listed"
	}
	parts := make([]string, 0, len(scope))
	for _, sc := range scope {
		parts = append(parts, regionLabel(sc))
	}
	return strings.Join(parts, "; ")
}

// subjectRegions is the watched scope compressed for a subject line.
func subjectRegions(ev incident.Event) string {
	r := ev.Record
	if r.Global {
		return "global"
	}
	scope := watchedScope(ev)
	if len(scope) == 0 {
		return "no region listed"
	}
	parts := make([]string, 0, maxSubjectRegions)
	for i, sc := range scope {
		if i == maxSubjectRegions {
			parts = append(parts, fmt.Sprintf("+%d more", len(scope)-maxSubjectRegions))
			break
		}
		parts = append(parts, regionLabel(sc))
	}
	return strings.Join(parts, "; ")
}

func regionLabel(sc incident.Scope) string {
	name := sc.RegionName
	if name == "" {
		name = sc.RegionCode
	}
	if len(sc.Services) == 0 {
		return name
	}
	abbrs := make([]string, 0, len(sc.Services))
	for _, sv := range sc.Services {
		a := sv.Abbr
		if a == "" {
			a = sv.Name
		}
		abbrs = append(abbrs, a)
	}
	return fmt.Sprintf("%s (%s)", name, strings.Join(abbrs, ", "))
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = "  " + strings.TrimSpace(l)
	}
	return strings.Join(lines, "\n")
}

// oneLine collapses whitespace including CR/LF. A title containing a newline
// would otherwise inject headers into an email or split a chat subject.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
