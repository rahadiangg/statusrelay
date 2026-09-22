package notify

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors every transport shares. Callers check these with errors.Is,
// so transports must wrap rather than replace them.
var (
	// ErrTransient means the delivery failed for a reason that may clear on
	// its own: a network error, a 5xx, a greylisting 4xx from SMTP. Worth
	// another attempt after a backoff.
	ErrTransient = errors.New("notify: transient delivery failure")

	// ErrPermanent means retrying cannot help: a rejected token, a chat the
	// bot is not in, a recipient the relay refuses. Surfaced at once so the
	// operator fixes the configuration instead of watching retries burn.
	ErrPermanent = errors.New("notify: permanent delivery failure")

	// ErrFiltered means the sink's route excluded the event: nothing was
	// sent and nothing failed. It is neither transient nor permanent, so the
	// retry decorator never sees it and the poller counts it as skipped
	// rather than as a delivery — a filtered event that reported "ok" would
	// make a mis-routed sink look healthy.
	ErrFiltered = errors.New("notify: event filtered by route")
)

// RateLimited is a transient failure where the remote said how long to wait.
// The retry decorator honours After instead of its own backoff, because
// retrying into a rate limit sooner than asked extends the limit.
type RateLimited struct {
	After time.Duration
	Err   error
}

func (r *RateLimited) Error() string {
	return fmt.Sprintf("rate limited, retry after %s: %v", r.After, r.Err)
}

func (r *RateLimited) Unwrap() error { return r.Err }

// Is makes errors.Is(err, ErrTransient) true for a RateLimited, so callers
// that only distinguish transient from permanent need no special case.
func (r *RateLimited) Is(target error) bool { return target == ErrTransient }
