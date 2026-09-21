package alibaba

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// Catalogue sanity thresholds.
//
// The live catalogue is 7 zones and 37 regions. The floors sit well under that
// so a region being retired does not trip them, and well over the size of a
// truncated or foreign response.
const (
	minZones   = 5
	minRegions = 25

	// sentinelZone and sentinelRegion must both be present for the response
	// to be the international catalogue at all. The pseudo-region is what
	// platform-wide events are tagged with, so its absence would also mean
	// those events stop being recognised as global.
	sentinelZone   = nonRegional
	sentinelRegion = "ap-southeast-1" // Singapore: the oldest international region
)

// Catalogue is the zone x region inventory.
//
// It contains no health information: it says what EXISTS, never what is
// working. Nothing downstream may derive a health signal from it.
type Catalogue struct {
	Regions []incident.Region
	byName  map[string]string // lowercased display name -> code
	byCode  map[string]string // code -> display name
	zones   int
	hasZone map[string]bool
}

// Region is re-exported for convenience at call sites.
type Region = incident.Region

func buildCatalogue(zs []wireZone) *Catalogue {
	c := &Catalogue{
		byName:  make(map[string]string),
		byCode:  make(map[string]string),
		hasZone: make(map[string]bool),
		zones:   len(zs),
	}
	for _, z := range zs {
		c.hasZone[z.Zone.ZoneID] = true
		for _, r := range z.RegionList {
			if r.RegionID == "" {
				continue
			}
			if _, seen := c.byCode[r.RegionID]; seen {
				continue
			}
			name := firstNonEmpty(r.RegionName, r.RegionID)
			c.Regions = append(c.Regions, incident.Region{Code: r.RegionID, Name: name})
			c.byCode[r.RegionID] = name
			c.byName[strings.ToLower(name)] = r.RegionID
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
//
// The dataset check runs first: a response that is the wrong corpus may well
// also be short, and "truncated" sends the operator to debug pagination when
// the problem is the URL.
func (c *Catalogue) Validate() error {
	if !c.hasZone[sentinelZone] {
		return fmt.Errorf("%w: catalogue has no %q zone", incident.ErrWrongDataset, sentinelZone)
	}
	if _, ok := c.byCode[sentinelRegion]; !ok {
		return fmt.Errorf("%w: catalogue has no %q region", incident.ErrWrongDataset, sentinelRegion)
	}
	if c.zones < minZones {
		return fmt.Errorf("%w: catalogue has %d zones, want at least %d", incident.ErrSchemaDrift, c.zones, minZones)
	}
	if len(c.Regions) < minRegions {
		return fmt.Errorf("%w: catalogue has %d regions, want at least %d",
			incident.ErrSchemaDrift, len(c.Regions), minRegions)
	}
	return nil
}

// ReconcileRegions checks configured codes and names against the live
// catalogue.
//
// This is the guard for the highest-consequence misconfiguration this service
// has: ap-southeast-1, -3 and -5 are Singapore, Kuala Lumpur and Jakarta, and
// choosing the wrong one produces no error at any layer.
//
// ponytail: duplicated from huawei; lift into incident when a third adapter
// needs it.
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
