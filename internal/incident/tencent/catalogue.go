package tencent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// Catalogue sanity thresholds.
//
// DescribeRegions has no pagination and no dataset selector, so the only
// truncation this guards against is a rewrite of the endpoint that returns a
// subset at HTTP 200. The international dashboard lists 18 regions.
const minCatalogueRegions = 15

// globalRegion is the pseudo-region the vendor uses for platform-wide events.
// It is a real, published scope value, not a parse artefact.
const globalRegion = "non-regional"

// sentinelRegion must be present for the catalogue to be the international
// dataset we built this against. It is also the region whose miscoding on a
// different provider motivated this whole project.
const sentinelRegion = "ap-jakarta"

// Catalogue is the region inventory plus the vendor's per-region "has an
// event" flag.
//
// It carries no health information: EventsIn says a region has a published
// event, not that a region without one is healthy.
type Catalogue struct {
	Regions  []incident.Region
	EventsIn map[string]bool   // region code -> vendor flag
	byName   map[string]string // lowercased display name -> code
	byCode   map[string]string // code -> display name
}

func buildCatalogue(w wireRegions) *Catalogue {
	c := &Catalogue{
		EventsIn: make(map[string]bool),
		byName:   make(map[string]string),
		byCode:   make(map[string]string),
	}
	for _, a := range w.Areas {
		for _, r := range a.Regions {
			code := strings.TrimSpace(r.ID)
			if code == "" {
				continue
			}
			if _, dup := c.byCode[code]; dup {
				c.EventsIn[code] = c.EventsIn[code] || r.EventsIn
				continue
			}
			name := strings.TrimSpace(r.Name)
			if name == "" {
				name = code
			}
			c.Regions = append(c.Regions, incident.Region{Code: code, Name: name})
			c.byCode[code] = name
			c.byName[strings.ToLower(name)] = code
			c.EventsIn[code] = r.EventsIn
		}
	}
	sort.Slice(c.Regions, func(i, j int) bool { return c.Regions[i].Code < c.Regions[j].Code })
	return c
}

// CodeFor resolves a display name to a region code.
func (c *Catalogue) CodeFor(name string) (string, bool) {
	code, ok := c.byName[strings.ToLower(strings.TrimSpace(name))]
	return code, ok
}

// NameFor resolves a region code to its display name.
func (c *Catalogue) NameFor(code string) (string, bool) {
	name, ok := c.byCode[code]
	return name, ok
}

// Validate asserts the catalogue is whole and is the dataset we expect.
func (c *Catalogue) Validate() error {
	if len(c.Regions) < minCatalogueRegions {
		return fmt.Errorf("%w: catalogue has %d regions, want at least %d",
			incident.ErrSchemaDrift, len(c.Regions), minCatalogueRegions)
	}
	if _, ok := c.byCode[sentinelRegion]; !ok {
		return fmt.Errorf("%w: catalogue lacks %s; this is not the international dashboard",
			incident.ErrWrongDataset, sentinelRegion)
	}
	if _, ok := c.byCode[globalRegion]; !ok {
		return fmt.Errorf("%w: catalogue lacks the %s pseudo-region; platform-wide events would be unscoped",
			incident.ErrSchemaDrift, globalRegion)
	}
	return nil
}

// ReconcileRegions checks configured codes and names against the live
// catalogue.
//
// A region id the server does not know is not an error anywhere upstream: the
// grid endpoint answers it with an empty catalogue at HTTP 200. This is the
// only place a typo becomes visible.
func (c *Catalogue) ReconcileRegions(codes, names []string) error {
	for _, code := range codes {
		if _, ok := c.byCode[code]; !ok {
			return fmt.Errorf("%w: configured region %q is not in the catalogue", incident.ErrBadRequest, code)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if len(names) != len(codes) {
		return fmt.Errorf("%w: %d region codes but %d region names; pair them or omit the names",
			incident.ErrBadRequest, len(codes), len(names))
	}
	for i, name := range names {
		got, ok := c.CodeFor(name)
		if !ok {
			return fmt.Errorf("%w: region name %q is not in the catalogue", incident.ErrBadRequest, name)
		}
		if got != codes[i] {
			return fmt.Errorf("%w: region %q is %q upstream, but the configuration pairs it with %q",
				incident.ErrBadRequest, name, got, codes[i])
		}
	}
	return nil
}
