package tencent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// seedEventCode is the fallback known-good probe target: the 2026-04-21 Seoul
// cooling incident. Once a newer event is observed the source probes with that
// instead, so history being pruned degrades the check rather than breaking it.
const seedEventCode = "93a75460e1115154b8cad11828c34ba7"

// SelfCheck proves the source is still telling the truth.
//
// An empty list from this API is not evidence of health: the same empty list
// comes back for an unknown event code and an unknown region, and a renamed
// endpoint differs only by an Error object we have to look for. The probes
// below turn "empty" into a distinguishable signal.
func (s *Source) SelfCheck(ctx context.Context) error {
	var errs []error

	if err := s.probeKnownEvent(ctx); err != nil {
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
	return errors.Join(errs...)
}

// probeKnownEvent asks for the timeline of an event that provably has one.
//
// The progress endpoint answers an unknown code with an empty list at HTTP
// 200. If a code we have already seen produce entries now returns none, then
// empty means nothing anywhere, and every quiet poll is suspect.
func (s *Source) probeKnownEvent(ctx context.Context) error {
	s.mu.Lock()
	code := s.learnedEvent.Code
	s.mu.Unlock()
	if code == "" {
		code = seedEventCode
	}
	ps, err := s.client.progress(ctx, code)
	if err != nil {
		return fmt.Errorf("known-event probe: %w", err)
	}
	if len(ps) == 0 {
		return fmt.Errorf("%w: event %s known to have a timeline returned none; "+
			"an empty result can no longer be trusted to mean 'nothing happened'",
			incident.ErrSchemaDrift, code)
	}
	return nil
}

// SelfCheckOK reports the last self-check outcome.
func (s *Source) SelfCheckOK() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selfCheckOK
}
