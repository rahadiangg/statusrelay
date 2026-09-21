package tencent

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// futureSlack is how far ahead of our clock a StartTime may sit before it is
// reported. Vendor and local clocks legitimately disagree by seconds; an hour
// means somebody parsed a zone wrong.
const futureSlack = 10 * time.Minute

// mapper turns wire rows into normalized records, accumulating anomalies as it
// goes rather than failing. A malformed field costs that field and a metric,
// never the incident.
type mapper struct {
	sourceID  string
	now       time.Time
	anomalies []incident.Warning

	// unkeyed counts rows dropped for lacking an EventCode. A row we cannot
	// key is a row whose absence next poll proves nothing, so the caller marks
	// the snapshot incomplete when this is non-zero.
	unkeyed int
}

func (m *mapper) warn(kind, detail string) {
	m.anomalies = append(m.anomalies, incident.Warning{Kind: kind, Detail: detail})
}

// mapEvents converts every row, splitting by status.
//
// Unknown status values land in open. The enum is undocumented and lifted from
// a minified bundle; a new value is far more likely to be a new kind of
// trouble than a new kind of "fine".
func (m *mapper) mapEvents(ws []wireEvent) (open, resolved []incident.Record) {
	seen := make(map[string]bool, len(ws))
	for i := range ws {
		w := &ws[i]
		code := strings.TrimSpace(w.EventCode)
		if code == "" {
			m.unkeyed++
			m.warn("unkeyed_event", "a row titled "+strconv.Quote(w.Title)+" has no EventCode and was dropped")
			continue
		}
		if seen[code] {
			// Pages are read in one pass; the first occurrence wins. Nothing
			// in the row is monotonic enough to prefer the second.
			m.warn(incident.AnomalyDuplicateID, "EventCode "+code+" appeared more than once")
			continue
		}
		seen[code] = true
		r := m.mapEvent(w, code)
		if r.Status == incident.StatusResolved {
			resolved = append(resolved, r)
		} else {
			open = append(open, r)
		}
	}
	sortRecords(open)
	sortRecords(resolved)
	return open, resolved
}

func sortRecords(rs []incident.Record) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Key.ProviderID < rs[j].Key.ProviderID })
}

func (m *mapper) mapEvent(w *wireEvent, code string) incident.Record {
	titles := map[string]string{}
	if t := strings.TrimSpace(w.Title); t != "" {
		titles["en"] = t
	} else {
		m.warn(incident.AnomalyEmptyDescription, "event "+code+" has no title")
	}
	title, lang := incident.PreferredTitle(titles, "en", code)

	status, sev, raw := m.grade(w, code)

	started := m.parseStamp(code, "start", w.StartTime)
	updated := m.parseStamp(code, "update", w.UpdateTime)
	ended := m.parseStamp(code, "end", w.EndTime)
	if !started.IsZero() && started.After(m.now.Add(futureSlack)) {
		m.warn(incident.AnomalyFutureTimestamp, "event "+code+" starts at "+started.Format(time.RFC3339)+", after now")
	}

	r := incident.Record{
		Key:         incident.Key{SourceID: m.sourceID, ProviderID: code},
		Title:       title,
		TitleLang:   lang,
		Titles:      titles,
		Severity:    sev,
		RawSeverity: raw,
		Status:      status,
		StartedAt:   started,
		UpdatedAt:   updated,
		Scope:       m.mapScope(code, w),
	}
	// Global comes from the wire shape: either the vendor published no region
	// (anomalous, warned above) or it published only the non-regional
	// pseudo-region (a real platform-wide event). Both are region-less and
	// both must alert.
	r.Global = len(r.Scope) == 0
	if status == incident.StatusResolved && !ended.IsZero() {
		r.EndedAt = ended
	}
	r.FP = incident.Compute(r)
	return r
}

// grade maps the vendor's status and exercise flag onto the contract.
//
// There is no severity field. An ongoing event grades Unknown so it always
// alerts; an informational one grades Info so an operator can filter it; a
// drill grades Info for the same reason. IsEnable is deliberately ignored: its
// meaning is unobserved, and dropping rows on an unobserved flag is how an
// outage goes unreported.
func (m *mapper) grade(w *wireEvent, code string) (status incident.Status, sev incident.Severity, raw string) {
	raw = w.Status.String()
	switch raw {
	case statusResolved:
		status, sev, raw = incident.StatusResolved, incident.SeverityUnknown, "normal"
	case statusOngoing:
		status, sev, raw = incident.StatusOpen, incident.SeverityUnknown, "unnormal"
	case statusInfo:
		status, sev, raw = incident.StatusOpen, incident.SeverityInfo, "info"
	default:
		m.warn(incident.AnomalyUnknownStatus, "event "+code+" has status "+strconv.Quote(raw))
		status, sev = incident.StatusOpen, incident.SeverityUnknown
	}
	if w.IsExercise {
		sev, raw = incident.SeverityInfo, "exercise"
	}
	return status, sev, raw
}

func (m *mapper) parseStamp(code, field, s string) time.Time {
	t, ok := parseTime(s)
	if !ok {
		m.warn(incident.AnomalyBadTimestamp, "event "+code+" "+field+" time "+strconv.Quote(s))
	}
	return t
}

// mapScope produces one Scope per real region, each carrying the whole product
// list: the API scopes products to the event, not to a region.
//
// The non-regional pseudo-region is dropped from Scope rather than kept as a
// region, so a record that names only it maps to Global and a record that
// names it alongside real regions keeps just the real ones. Filter treats
// Global and "matches my region" as separate questions, which is what an
// operator watching one region wants.
func (m *mapper) mapScope(code string, w *wireEvent) []incident.Scope {
	if len(w.Regions) == 0 {
		m.warn(incident.AnomalyNullScope, "event "+code+" published no region")
		return nil
	}
	services := make([]incident.Service, 0, len(w.Products))
	for _, p := range w.Products {
		id := strings.TrimSpace(p.ID)
		if id == "" {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = id
		}
		services = append(services, incident.Service{ID: id, Name: name, Abbr: strings.ToUpper(id)})
	}
	sort.SliceStable(services, func(i, j int) bool { return services[i].ID < services[j].ID })

	var out []incident.Scope
	seen := make(map[string]bool, len(w.Regions))
	for _, r := range w.Regions {
		id := strings.TrimSpace(r.ID)
		if id == "" || id == globalRegion || seen[id] {
			continue
		}
		seen[id] = true
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = id
		}
		out = append(out, incident.Scope{
			RegionID:   id,
			RegionCode: id,
			RegionName: name,
			Services:   append([]incident.Service(nil), services...),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RegionCode < out[j].RegionCode })
	return out
}

// mapProgress converts a timeline. Entries without text are dropped: they
// would add a phantom update and trigger a spurious notification.
//
// The API publishes newest-first, so the list is walked backwards before the
// contract's ascending check; otherwise every real record would be flagged
// out-of-order forever and the anomaly would mean nothing.
func (m *mapper) mapProgress(code string, ps []wireProgress) []incident.Update {
	if len(ps) == 0 {
		return nil
	}
	out := make([]incident.Update, 0, len(ps))
	for i := len(ps) - 1; i >= 0; i-- {
		p := ps[i]
		text := strings.TrimSpace(p.Content)
		if text == "" {
			continue
		}
		at := m.parseStamp(code, "progress", p.OccurTime)
		out = append(out, incident.Update{
			At:   at,
			Text: text,
			Lang: "en",
			Hash: incident.HashUpdateText(at, text),
		})
	}
	sorted, wasOrdered := incident.SortUpdates(out)
	if !wasOrdered {
		m.warn(incident.AnomalyProgressOutOfOrder, "event "+code+" progress entries were not chronological")
	}
	return sorted
}
