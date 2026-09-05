package huawei

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// Catalogue sanity thresholds.
//
// These exist to catch the truncated-page failure: without an explicit limit the
// API returns 1000 rows covering 9 of 17 regions, at HTTP 200. Note that the
// watched region may well still be present in that truncated page — checking
// only "can I find AP-Jakarta?" does NOT catch it. Only the totals do.
const (
	minCatalogueRows    = 1200 // 1579 observed
	minCatalogueRegions = 15   // 17 observed
)

// Catalogue is the region x service inventory.
//
// It contains no health information of any kind: it says what EXISTS, never
// what is working. The vendor's own green-tick grid is a client-side projection
// of published incidents onto this list, which is why this service must never
// emit a per-service health signal derived from it.
type Catalogue struct {
	Regions      []incident.Region
	byName       map[string]string // lowercased display name -> code
	byCode       map[string]string // code -> display name
	rows         int
	cnRegionFrac float64
}

// Region is re-exported for convenience at call sites.
type Region = incident.Region

func buildCatalogue(rows []wireServiceRow) *Catalogue {
	c := &Catalogue{
		byName: make(map[string]string),
		byCode: make(map[string]string),
		rows:   len(rows),
	}
	var cn int
	seen := make(map[string]bool)
	for _, r := range rows {
		if r.RegionCode == "" {
			continue
		}
		if !seen[r.RegionCode] {
			seen[r.RegionCode] = true
			name := firstNonEmpty(r.RegionEN, r.RegionZH, r.RegionCode)
			c.Regions = append(c.Regions, incident.Region{Code: r.RegionCode, Name: name})
			c.byCode[r.RegionCode] = name
			c.byName[strings.ToLower(name)] = r.RegionCode
			if strings.HasPrefix(r.RegionCode, "cn-") {
				cn++
			}
		}
	}
	sort.Slice(c.Regions, func(i, j int) bool { return c.Regions[i].Code < c.Regions[j].Code })
	if len(c.Regions) > 0 {
		c.cnRegionFrac = float64(cn) / float64(len(c.Regions))
	}
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
func (c *Catalogue) Validate(allowNonIntl bool) error {
	if c.rows < minCatalogueRows {
		return fmt.Errorf("%w: catalogue has %d rows, want at least %d; "+
			"a short catalogue means the response was truncated and some regions are missing entirely",
			incident.ErrSchemaDrift, c.rows, minCatalogueRows)
	}
	if len(c.Regions) < minCatalogueRegions {
		return fmt.Errorf("%w: catalogue has %d regions, want at least %d",
			incident.ErrSchemaDrift, len(c.Regions), minCatalogueRegions)
	}
	// A catalogue that is overwhelmingly mainland regions means we are reading
	// the other site's dataset, which happens silently when the base URL loses
	// its path prefix.
	if !allowNonIntl && c.cnRegionFrac > 0.9 {
		return fmt.Errorf("%w: %.0f%% of regions are mainland; the base URL has probably lost its path prefix",
			incident.ErrWrongDataset, c.cnRegionFrac*100)
	}
	return nil
}

// ReconcileRegions checks configured codes and names against the live
// catalogue.
//
// This is the guard for the highest-consequence misconfiguration this service
// has: neighbouring region codes differ by one trailing character, and choosing
// the wrong one produces no error at any layer. The watcher simply monitors a
// different country forever while reporting perfectly healthy.
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
