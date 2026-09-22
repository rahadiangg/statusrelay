package huawei

import (
	"sort"
	"strconv"
	"strings"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// mapper turns wire records into normalized ones, accumulating anomalies as it
// goes rather than failing.
//
// The guiding rule: a payload that parses at all should yield every record it
// contains. A malformed field costs us that field and a metric; it must never
// cost us the incident, because the whole point of this service is to not miss
// one.
type mapper struct {
	sourceID   string
	page       func(id string) string
	preferLang string
	levels     map[int64]incident.Severity
	anomalies  []incident.Warning
}

func (m *mapper) warn(kind, detail string) {
	m.anomalies = append(m.anomalies, incident.Warning{Kind: kind, Detail: detail})
}

// mapEvents converts a decoded response, resolving duplicates and sorting the
// result so two identical payloads always produce identical output.
func (m *mapper) mapEvents(ws []wireEvent, status incident.Status) []incident.Record {
	byID := make(map[string]incident.Record, len(ws))
	order := make([]string, 0, len(ws))

	for i := range ws {
		r := m.mapEvent(&ws[i], status)
		if prev, dup := byID[r.Key.ProviderID]; dup {
			m.warn(incident.AnomalyDuplicateID, "event_id "+r.Key.ProviderID+" appeared more than once")
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
	// Sort by id so downstream comparisons and golden files are stable
	// regardless of the order the API happened to use.
	sort.SliceStable(out, func(i, j int) bool {
		return lessID(out[i].Key.ProviderID, out[j].Key.ProviderID)
	})
	return out
}

// pickDuplicate chooses deterministically between two records sharing an id.
//
// Newer mtime wins; failing that, the one with more progress entries, which is
// the only other monotonic signal available. Payload order is the final
// tiebreak so the outcome never depends on map iteration.
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

// lessID orders numeric ids numerically and anything else lexically, so 9 sorts
// before 13 rather than after it.
func lessID(a, b string) bool {
	na, aerr := strconv.ParseInt(a, 10, 64)
	nb, berr := strconv.ParseInt(b, 10, 64)
	if aerr == nil && berr == nil {
		return na < nb
	}
	return a < b
}

func (m *mapper) mapEvent(w *wireEvent, status incident.Status) incident.Record {
	id := w.EventID.String()

	titles := map[string]string{}
	if strings.TrimSpace(w.DescEN) != "" {
		titles["en"] = w.DescEN
	}
	if strings.TrimSpace(w.DescZH) != "" {
		titles["zh"] = w.DescZH
	}
	if len(titles) == 0 {
		m.warn(incident.AnomalyEmptyDescription, "event "+id+" has no description in any language")
	} else if _, ok := titles[m.preferLang]; !ok {
		m.warn(incident.AnomalyEmptyDescription, "event "+id+" has no "+m.preferLang+" description")
	}
	title, lang := incident.PreferredTitle(titles, m.preferLang, id)

	sev, known := m.levels[w.EventLvl.Value]
	if !known {
		// An unrecognised level is not a reason to drop or downgrade: the
		// severity domain here is undocumented and has gained values before.
		sev = incident.SeverityUnknown
		m.warn(incident.AnomalyUnknownSeverity, "event "+id+" has level "+w.EventLvl.String())
	}

	started, ok := parseTime(w.OccurTime)
	if !ok && strings.TrimSpace(w.OccurTime) != "" {
		m.warn(incident.AnomalyBadTimestamp, "event "+id+" occur time "+strconv.Quote(w.OccurTime))
	}
	updated, ok := parseTime(w.LastUpdate)
	if !ok && strings.TrimSpace(w.LastUpdate) != "" {
		m.warn(incident.AnomalyBadTimestamp, "event "+id+" update time "+strconv.Quote(w.LastUpdate))
	}

	r := incident.Record{
		Key:         incident.Key{SourceID: m.sourceID, ProviderID: id},
		URL:         m.page(id),
		Title:       title,
		TitleLang:   lang,
		Titles:      titles,
		Severity:    sev,
		RawSeverity: w.EventLvl.String(),
		Status:      status,
		StartedAt:   started,
		UpdatedAt:   updated,
		HasReport:   w.HasReport,
		Updates:     m.mapProgress(id, w.Progress),
		Scope:       m.mapScope(w.ExtInfos),
	}

	// Global is set from the WIRE shape, not from len(Scope) after mapping.
	// The distinction matters: "the vendor published no region" is a real,
	// alertable platform-wide event, and collapsing it into an empty slice
	// would let a downstream len()==0 check silently drop total outages.
	//
	// Both wire shapes land here: a null event_ext_infos decodes to a nil
	// slice, an empty array to an empty one, and Go treats their lengths
	// identically. They mean the same thing upstream, so they map the same way.
	if len(w.ExtInfos) == 0 {
		r.Global = true
		m.warn(incident.AnomalyNullScope, "event "+id+" published no region")
	}

	if status == incident.StatusResolved && !updated.IsZero() {
		r.EndedAt = updated
	}

	r.FP = incident.Compute(r)
	return r
}

func (m *mapper) mapProgress(id string, ps []wireProgress) []incident.Update {
	if len(ps) == 0 {
		return nil
	}
	out := make([]incident.Update, 0, len(ps))
	for _, p := range ps {
		text, lang := incident.PreferredTitle(
			map[string]string{"en": p.EN, "zh": p.ZH}, m.preferLang, id)
		if lang == "none" {
			// An entry with no text in any language carries no information;
			// keeping it would add a phantom update to the progress count and
			// trigger a spurious notification.
			continue
		}
		at, ok := parseTime(p.Time)
		if !ok && strings.TrimSpace(p.Time) != "" {
			m.warn(incident.AnomalyBadTimestamp, "event "+id+" progress time "+strconv.Quote(p.Time))
		}
		out = append(out, incident.Update{
			At:   at,
			Text: strings.TrimSpace(text),
			Lang: lang,
			Hash: incident.HashUpdateText(at, strings.TrimSpace(text)),
		})
	}
	sorted, wasOrdered := incident.SortUpdates(out)
	if !wasOrdered {
		m.warn(incident.AnomalyProgressOutOfOrder, "event "+id+" progress entries were not chronological")
	}
	return sorted
}

func (m *mapper) mapScope(exts []wireExtInfo) []incident.Scope {
	if len(exts) == 0 {
		return nil
	}
	out := make([]incident.Scope, 0, len(exts))
	for _, e := range exts {
		sc := incident.Scope{
			RegionID:   e.RegionID,
			RegionCode: e.RegionCode,
			RegionName: firstNonEmpty(e.RegionEN, e.RegionZH, e.RegionCode),
		}
		for _, s := range e.Services {
			sc.Services = append(sc.Services, incident.Service{
				ID:   s.ID,
				Name: firstNonEmpty(s.EN, s.ZH, s.Abbr),
				Abbr: s.Abbr,
			})
		}
		// Sorting here rather than at fingerprint time keeps the record itself
		// stable, so notifications and the dashboard also stop reordering
		// between polls of identical data.
		sort.SliceStable(sc.Services, func(i, j int) bool { return sc.Services[i].ID < sc.Services[j].ID })
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

// defaultLevels is the severity mapping for this vendor.
//
// Only levels 1 (China site) and 2 (international) have ever been observed. The
// domain is undocumented, so the map is configurable and anything absent from it
// grades as Unknown and still alerts.
func defaultLevels() map[int64]incident.Severity {
	return map[int64]incident.Severity{
		1: incident.SeverityMajor,
		2: incident.SeverityCritical,
	}
}
