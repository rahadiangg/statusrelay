package huawei

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
)

// seedEventID is the fallback known-good probe target: the only incident this
// vendor has ever published on the international site.
//
// It is a seed, not a constant to rely on. Once a newer event is observed the
// source probes with that instead, so pruned history degrades the check rather
// than breaking it.
const seedEventID = "13"

// seedWindowStart predates the earliest record the dashboard exposes.
var seedWindowStart = time.Date(2022, 9, 24, 0, 0, 0, 0, time.UTC)

// SelfCheck proves the source is still telling the truth.
//
// It exists because an empty array from this API is not evidence of health.
// The same empty array is returned when a query parameter is silently ignored,
// when a required parameter is missing, and when the endpoint has been renamed.
// Each probe below turns one of those into a distinguishable signal.
func (s *Source) SelfCheck(ctx context.Context) error {
	var errs []error

	if err := s.probeKnownWindow(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.probeRejectsBadParameter(ctx); err != nil {
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

// probeKnownWindow asks for a time window that provably contained an incident.
//
// This is the most valuable single check in the service. If a window that we
// have already seen produce a record now returns nothing, then an empty array
// means nothing anywhere, and every "all clear" the poller reports is suspect.
func (s *Source) probeKnownWindow(ctx context.Context) error {
	s.mu.Lock()
	learned := s.learnedEvent
	s.mu.Unlock()

	start, wantID := seedWindowStart, seedEventID
	if learned.ID != "" && !learned.At.IsZero() {
		// Widen by a minute so a second-precision boundary cannot exclude the
		// very record we are probing for.
		start, wantID = learned.At.Add(-time.Minute), learned.ID
	}

	ws, err := s.client.historyEvents(ctx, start, time.Time{})
	if err != nil {
		return fmt.Errorf("known-window probe: %w", err)
	}
	for _, w := range ws {
		if w.EventID.String() == wantID {
			return nil
		}
	}
	if len(ws) == 0 {
		return fmt.Errorf("%w: a window known to contain event %s returned no records; "+
			"an empty result can no longer be trusted to mean 'no incidents'",
			incident.ErrSchemaDrift, wantID)
	}
	return fmt.Errorf("%w: event %s absent from a window that should contain it (%d records returned)",
		incident.ErrSchemaDrift, wantID, len(ws))
}

// probeRejectsBadParameter sends a deliberately malformed timestamp.
//
// A healthy API rejects it with a 400 and a specific error code. If it answers
// 200 with an empty array instead, parameter validation has changed and every
// parameterised query we make may be silently returning nothing.
func (s *Source) probeRejectsBadParameter(ctx context.Context) error {
	u, err := joinBad(s.client.base)
	if err != nil {
		return err
	}
	var out []wireEvent
	_, err = s.client.http.GetJSON(ctx, u, &out)
	switch {
	case errors.Is(err, incident.ErrBadRequest):
		return nil // the expected, healthy answer
	case err == nil:
		return fmt.Errorf("%w: a malformed timestamp was accepted and returned %d records; "+
			"parameter validation has changed, so empty results are no longer meaningful",
			incident.ErrSchemaDrift, len(out))
	default:
		// Anything else (a block, a transport failure) is not evidence about
		// validation, so it is not this probe's business to report.
		return nil
	}
}

func joinBad(base string) (string, error) {
	u := strings.TrimSuffix(base, "/") + "/" + pathHistoryEvents + "?start_time=2022-09-24"
	if !strings.Contains(u, "://") {
		return "", fmt.Errorf("%w: base url %q", incident.ErrBadRequest, base)
	}
	return u, nil
}

// SelfCheckOK reports the last self-check outcome, so the poller can mark a
// snapshot incomplete without re-running the probes on every cycle.
func (s *Source) SelfCheckOK() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selfCheckOK
}
