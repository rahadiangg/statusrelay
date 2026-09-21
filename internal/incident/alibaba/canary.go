package alibaba

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/incident/httpx"
)

// Seed probe target: the newest incident on the international site when this
// adapter was written. It is a seed, not a constant to rely on; once a newer
// event is observed the source probes with that instead.
var seed = learnedEvent{
	ID:       "35",
	RegionID: "ap-southeast-5",
	Start:    time.UnixMilli(1785214500000).UTC(),
	End:      time.UnixMilli(1785230700000).UTC(),
}

// SelfCheck proves the source is still telling the truth.
//
// An empty list from this API is not evidence of health: the same empty list
// comes back for an unknown event id, for a region code that does not exist,
// and (with success:true) for any month nothing happened. Each probe turns one
// of those into a distinguishable signal.
func (s *Source) SelfCheck(ctx context.Context) error {
	var errs []error

	s.mu.Lock()
	probe := s.learned
	s.mu.Unlock()
	if probe.ID == "" {
		probe = seed
	}

	if err := s.probeKnownEvent(ctx, probe); err != nil {
		errs = append(errs, err)
	}
	if err := s.probeRegionHonoured(ctx, probe); err != nil {
		errs = append(errs, err)
	}
	if err := s.probeRejectsMissingRegion(ctx); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.Catalogue(ctx, 6*time.Hour); err != nil {
		errs = append(errs, fmt.Errorf("catalogue check: %w", err))
	} else if err := s.ValidateRegions(ctx); err != nil {
		errs = append(errs, fmt.Errorf("region check: %w", err))
	}

	ok := len(errs) == 0
	s.mu.Lock()
	s.selfCheckOK = ok
	s.mu.Unlock()

	if !ok {
		return errors.Join(errs...)
	}
	return nil
}

// probeKnownEvent asks for an event that provably exists.
//
// If an id we have already seen now returns nothing, then an empty result
// means nothing anywhere, and every "all clear" the poller reports is suspect.
func (s *Source) probeKnownEvent(ctx context.Context, p learnedEvent) error {
	ev, found, err := s.client.detail(ctx, p.ID)
	if err != nil {
		return fmt.Errorf("known-event probe: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: event %s is known to exist but its detail returned nothing; "+
			"an empty result can no longer be trusted to mean 'no incidents'", incident.ErrSchemaDrift, p.ID)
	}
	if got := ev.ID.String(); got != p.ID {
		return fmt.Errorf("%w: asked for event %s, detail returned event %s", incident.ErrSchemaDrift, p.ID, got)
	}
	return nil
}

// probeRegionHonoured asks the per-region history for a window that provably
// contained an event in that region.
//
// This is the guard against the region filter turning into a no-op: the
// endpoint answers a region it does not know with a full page of empty days
// at success:true, and would answer an ignored parameter the same way.
func (s *Source) probeRegionHonoured(ctx context.Context, p learnedEvent) error {
	if p.RegionID == "" || p.Start.IsZero() {
		p = seed
	}
	end := p.End
	if end.IsZero() {
		end = s.clock.Now()
	}
	// Widen by a day on each side so a bucket boundary cannot exclude the
	// very record we are probing for.
	end = end.Add(24 * time.Hour)
	span := end.Sub(p.Start.Add(-24 * time.Hour))
	days := int(span/(24*time.Hour)) + 2

	ds, err := s.client.period(ctx, p.RegionID, end, days)
	if err != nil {
		return fmt.Errorf("region probe: %w", err)
	}
	for _, d := range ds {
		if _, ok := d.ProductStatusDetail.EventDetails[p.ID]; ok {
			return nil
		}
	}
	return fmt.Errorf("%w: region %s over a window known to contain event %s returned no such event (%d days); "+
		"regionId is no longer honoured, so region filtering cannot be trusted",
		incident.ErrSchemaDrift, p.RegionID, p.ID, len(ds))
}

// probeRejectsMissingRegion sends a period request with no regionId.
//
// A healthy API rejects it with code 400 in the envelope. If it answers with
// success instead, parameter validation has changed — and since a bogus
// region was already answered with silence, every region query we make may
// now be silently empty.
func (s *Source) probeRejectsMissingRegion(ctx context.Context) error {
	q := url.Values{"endTime": {formatMS(s.clock.Now())}, "numOfDay": {strconv.Itoa(1)}}
	u, err := httpx.JoinPath(s.client.base, pathPeriod, q)
	if err != nil {
		return err
	}
	var env envelope
	if _, err := s.client.http.GetJSON(ctx, u, &env); err != nil {
		// A block or a transport failure is not evidence about validation.
		return nil
	}
	err = classifyEnvelope(env)
	switch {
	case errors.Is(err, incident.ErrBadRequest):
		return nil // the expected, healthy answer
	case err == nil:
		return fmt.Errorf("%w: a period request with no regionId was accepted; "+
			"parameter validation has changed, so empty region results are no longer meaningful",
			incident.ErrSchemaDrift)
	default:
		return nil
	}
}

// SelfCheckOK reports the last self-check outcome.
func (s *Source) SelfCheckOK() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selfCheckOK
}
