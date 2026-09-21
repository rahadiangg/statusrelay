package alibaba

import (
	"sort"
	"strconv"
	"strings"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// nonRegional is the region id the vendor attaches to platform-wide events.
//
// It is a real entry in the region catalogue, not a null, so a naive reader
// would treat it as one more region nobody configured and drop the one class
// of event that affects everybody.
const nonRegional = "non-regional"

// severities maps the vendor's eventType to the normalized ladder. Only two
// values have ever been observed; anything else grades as Unknown and alerts.
var severities = map[string]incident.Severity{
	"ALARM":        incident.SeverityMajor,
	"NOTIFICATION": incident.SeverityInfo,
}

// mapper turns wire records into normalized ones, accumulating anomalies as it
// goes rather than failing. A payload that parses at all yields every record
// it contains; a malformed field costs that field and a metric, never the
// incident.
type mapper struct {
	sourceID  string
	anomalies []incident.Warning
}

func (m *mapper) warn(kind, detail string) {
	m.anomalies = append(m.anomalies, incident.Warning{Kind: kind, Detail: detail})
}

// mapEvents converts a decoded list, resolving duplicates and sorting so two
// identical payloads always produce identical output.
func (m *mapper) mapEvents(ws []wireEvent, status incident.Status) []incident.Record {
	byID := make(map[string]incident.Record, len(ws))
	order := make([]string, 0, len(ws))

	for i := range ws {
		r := m.mapEvent(&ws[i], status)
		if prev, dup := byID[r.Key.ProviderID]; dup {
			m.warn(incident.AnomalyDuplicateID, "event "+r.Key.ProviderID+" appeared more than once")
			byID[r.Key.ProviderID] = pickDuplicate(prev, r)
			continue
		}
		byID[r.Key.ProviderID] = r
		order = append(order, r.Key.ProviderID)
	}

	out := make([]incident.Record, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return lessID(out[i].Key.ProviderID, out[j].Key.ProviderID)
	})
	return out
}

// pickDuplicate chooses deterministically between two records sharing an id:
// newer mtime, then more progress entries, then payload order.
func pickDuplicate(a, b incident.Record) incident.Record {
	if !a.UpdatedAt.Equal(b.UpdatedAt) {
		if b.UpdatedAt.After(a.UpdatedAt) {
			return b
		}
		return a
	}
	if len(b.Updates) > len(a.Updates) {
		return b
	}
	return a
}

// lessID orders numeric ids numerically and anything else lexically.
func lessID(a, b string) bool {
	na, aerr := strconv.ParseInt(a, 10, 64)
	nb, berr := strconv.ParseInt(b, 10, 64)
	if aerr == nil && berr == nil {
		return na < nb
	}
	return a < b
}

func (m *mapper) mapEvent(w *wireEvent, status incident.Status) incident.Record {
	id := w.ID.String()

	titles := map[string]string{}
	if strings.TrimSpace(w.Title) != "" {
		titles["en"] = w.Title
	} else {
		m.warn(incident.AnomalyEmptyDescription, "event "+id+" has no title")
	}
	title, lang := incident.PreferredTitle(titles, "en", id)

	sev, known := severities[w.EventType]
	if !known {
		sev = incident.SeverityUnknown
		m.warn(incident.AnomalyUnknownSeverity, "event "+id+" has eventType "+strconv.Quote(w.EventType))
	}

	for _, ts := range []struct {
		name string
		v    msTime
	}{{"startTime", w.StartTime}, {"endTime", w.EndTime}, {"lastUpdateTime", w.LastUpdateTime}} {
		if ts.v.Bad {
			m.warn(incident.AnomalyBadTimestamp, "event "+id+" "+ts.name+" is not epoch milliseconds")
		}
	}

	r := incident.Record{
		Key:         incident.Key{SourceID: m.sourceID, ProviderID: id},
		Title:       title,
		TitleLang:   lang,
		Titles:      titles,
		Severity:    sev,
		RawSeverity: w.EventType,
		Status:      status,
		StartedAt:   w.StartTime.T,
		UpdatedAt:   w.LastUpdateTime.T,
		EndedAt:     w.EndTime.T,
		Updates:     m.mapUpdates(id, w.EventUpdates),
		Scope:       m.mapScope(w.Regions, w.Products),
	}

	// Which list a record came from decides its status; endTime only
	// corroborates. When the two disagree the list wins, because an "open"
	// row with an end time is far more likely a vendor still finalising the
	// record than a resolved incident, and the reverse would silently close
	// an outage on the strength of one field.
	switch {
	case status == incident.StatusOpen && w.EndTime.Set:
		m.warn(incident.AnomalyStatusConflict, "event "+id+" is listed open but carries an endTime")
	case status == incident.StatusResolved && !w.EndTime.Set:
		m.warn(incident.AnomalyStatusConflict, "event "+id+" is listed resolved but has no endTime")
	}

	// Global is set from the WIRE shape. A null regions list is the vendor
	// saying "no region"; the non-regional pseudo-region is the vendor saying
	// "every region". Both are platform-wide and both must reach a deployment
	// that watches one country, so both fail open.
	if len(w.Regions) == 0 {
		r.Global = true
		m.warn(incident.AnomalyNullScope, "event "+id+" published no region")
	}
	for _, reg := range w.Regions {
		if reg.RegionID == nonRegional {
			r.Global = true
		}
	}

	r.FP = incident.Compute(r)
	return r
}

// mapUpdates turns HTML progress entries into text, oldest first.
//
// The vendor sends them newest first. They are reversed before sorting so the
// out-of-order anomaly means "the vendor's order was not monotonic" rather
// than firing on every single record.
func (m *mapper) mapUpdates(id string, us []wireUpdate) []incident.Update {
	if len(us) == 0 {
		return nil
	}
	out := make([]incident.Update, 0, len(us))
	for i := len(us) - 1; i >= 0; i-- {
		u := us[i]
		text := stripHTML(u.Content)
		if text == "" {
			// No text is no information; keeping it would add a phantom
			// update and fire a spurious notification.
			continue
		}
		if u.PublishTime.Bad {
			m.warn(incident.AnomalyBadTimestamp, "event "+id+" update "+u.ID.String()+" publishTime is not epoch milliseconds")
		}
		out = append(out, incident.Update{
			At:   u.PublishTime.T,
			Text: text,
			Lang: "en",
			Hash: incident.HashUpdateText(u.PublishTime.T, text),
		})
	}
	sorted, wasOrdered := incident.SortUpdates(out)
	if !wasOrdered {
		m.warn(incident.AnomalyProgressOutOfOrder, "event "+id+" progress entries were not chronological")
	}
	return sorted
}

// mapScope builds one Scope per region, each carrying every product.
//
// The vendor publishes products and regions as two flat lists, not as
// products-per-region, so the cross product is the most faithful reading. A
// record with products but no regions yields no scope at all (it is Global);
// the products are dropped, which is lossy but honest — there is no region
// to attach them to.
func (m *mapper) mapScope(regions []wireRegion, products []wireProduct) []incident.Scope {
	if len(regions) == 0 {
		return nil
	}
	services := make([]incident.Service, 0, len(products))
	for _, p := range products {
		if strings.TrimSpace(p.ProductID) == "" {
			continue
		}
		services = append(services, incident.Service{
			ID:   p.ProductID,
			Name: firstNonEmpty(p.ProductName, p.ProductID),
			Abbr: strings.ToUpper(p.ProductID),
		})
	}
	sort.SliceStable(services, func(i, j int) bool { return services[i].ID < services[j].ID })

	out := make([]incident.Scope, 0, len(regions))
	for _, reg := range regions {
		if strings.TrimSpace(reg.RegionID) == "" {
			continue
		}
		sc := incident.Scope{
			RegionID:   reg.RegionID,
			RegionCode: reg.RegionID,
			RegionName: firstNonEmpty(reg.RegionName, reg.RegionID),
		}
		if len(services) > 0 {
			sc.Services = append([]incident.Service(nil), services...)
		}
		out = append(out, sc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RegionCode < out[j].RegionCode })
	return out
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
