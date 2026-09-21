package notify

import (
	"fmt"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// Health event kinds. They describe statusrelay's ability to see a provider,
// not the provider's incidents, and travel through the same sinks because a
// watcher that has gone blind looks exactly like a healthy provider to anyone
// who is not told otherwise.
//
// They live here rather than in the contract package: incident describes what
// a provider publishes, and the poller's own health is not that.
const (
	KindSourceBlind     incident.EventKind = "source_blind"
	KindSourceRecovered incident.EventKind = "source_recovered"
)

// healthProviderID is the synthetic record id used for health events, so a
// receiver threading on Key groups every blind/recovered pair per source.
const healthProviderID = "statusrelay"

// SourceBlind builds the event for a source that has produced no complete
// snapshot for longer than the configured threshold. reason is the last fetch
// error or the snapshot warnings, quoted verbatim so the alert is actionable.
func SourceBlind(sourceID, reason string, since, now time.Time) incident.Event {
	r := healthRecord(sourceID, now)
	r.Title = fmt.Sprintf("statusrelay cannot see %s (no complete snapshot for %s)", sourceID, now.Sub(since).Round(time.Second))
	r.Status = incident.StatusOpen
	r.StartedAt = since
	r.Updates = []incident.Update{{At: now, Text: reason, Lang: "en", Hash: incident.HashUpdateText(now, reason)}}
	r.FP = incident.Compute(r)
	return incident.Event{Kind: KindSourceBlind, Record: r, NewUpdates: r.Updates}
}

// SourceRecovered builds the event for a source that produced a complete
// snapshot again after being blind.
func SourceRecovered(sourceID string, blindFor time.Duration, now time.Time) incident.Event {
	r := healthRecord(sourceID, now)
	r.Title = fmt.Sprintf("statusrelay can see %s again (blind for %s)", sourceID, blindFor.Round(time.Second))
	r.Status = incident.StatusResolved
	r.StartedAt = now.Add(-blindFor)
	r.EndedAt = now
	text := "A complete snapshot was received. Incidents published while blind, if any, will be reported now."
	r.Updates = []incident.Update{{At: now, Text: text, Lang: "en", Hash: incident.HashUpdateText(now, text)}}
	r.FP = incident.Compute(r)
	return incident.Event{Kind: KindSourceRecovered, Record: r, NewUpdates: r.Updates}
}

func healthRecord(sourceID string, now time.Time) incident.Record {
	return incident.Record{
		Key:       incident.Key{SourceID: sourceID, ProviderID: healthProviderID},
		TitleLang: "en",
		// Critical because the consequence of ignoring it is the one CLAUDE.md
		// names as the most likely way this tool causes harm: silence read
		// as health.
		Severity:    incident.SeverityCritical,
		RawSeverity: "statusrelay",
		Global:      true,
		UpdatedAt:   now,
	}
}
