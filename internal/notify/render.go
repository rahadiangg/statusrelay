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

const timeLayout = "2006-01-02 15:04 UTC"

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

// Render produces the message for one event.
//
// Only NewUpdates are quoted, never the full history: an incident with thirty
// progress entries would otherwise resend all thirty on every change.
func Render(ev incident.Event) Message {
	r := ev.Record
	label := kindLabels[ev.Kind]
	if label == "" {
		// An unknown kind is a programming error upstream, but a blank label
		// would hide it; the raw kind at least shows what happened.
		label = strings.ToUpper(string(ev.Kind))
	}
	sev := severityLabel(r)

	var b strings.Builder
	fmt.Fprintf(&b, "%s · %s · %s #%s\n", label, sev, r.Key.SourceID, r.Key.ProviderID)
	fmt.Fprintf(&b, "%s\n", r.Title)
	fmt.Fprintf(&b, "Status: %s\n", r.Status)
	if !r.StartedAt.IsZero() {
		fmt.Fprintf(&b, "Published: %s\n", fmtTime(r.StartedAt))
	}
	if !r.EndedAt.IsZero() {
		fmt.Fprintf(&b, "Ended: %s\n", fmtTime(r.EndedAt))
	}
	fmt.Fprintf(&b, "Regions: %s\n", regions(r))
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
			fmt.Fprintf(&b, "Update %s:\n", fmtTime(u.At))
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

	return Message{
		Subject: oneLine(fmt.Sprintf("[statusrelay] %s %s: %s", label, sev, r.Title)),
		Body:    strings.TrimRight(b.String(), "\n") + "\n",
	}
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

// regions renders the scope. A global record and a record with an empty scope
// are different shapes and must read differently: the first is a platform-wide
// event, the second is the provider naming nothing.
func regions(r incident.Record) string {
	if r.Global {
		return "global (no region published)"
	}
	if len(r.Scope) == 0 {
		return "none listed"
	}
	parts := make([]string, 0, len(r.Scope))
	for _, sc := range r.Scope {
		name := sc.RegionName
		if name == "" {
			name = sc.RegionCode
		}
		if len(sc.Services) == 0 {
			parts = append(parts, name)
			continue
		}
		abbrs := make([]string, 0, len(sc.Services))
		for _, sv := range sc.Services {
			a := sv.Abbr
			if a == "" {
				a = sv.Name
			}
			abbrs = append(abbrs, a)
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", name, strings.Join(abbrs, ", ")))
	}
	return strings.Join(parts, "; ")
}

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

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
