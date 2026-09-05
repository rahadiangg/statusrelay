package incident

import "errors"

// Sentinel errors every adapter shares. Callers check these with errors.Is, so
// adapters must wrap rather than replace them.
var (
	// ErrEndpointGone means the upstream reports the route no longer exists.
	//
	// This is separate from a generic server error on purpose. At least one
	// upstream returns HTTP 500 — not 404 — for a removed endpoint, so folding
	// it into ordinary 5xx retry noise would hide a permanent API removal
	// behind "transient, will retry" for weeks.
	ErrEndpointGone = errors.New("incident: upstream endpoint no longer exists")

	// ErrBlocked means a WAF or bot-detection layer refused the request.
	// Retrying deepens the block; the caller must fail over or back off.
	ErrBlocked = errors.New("incident: request blocked by upstream protection")

	// ErrNotJSON means the response was well-formed HTTP but not the JSON we
	// expect — typically an HTML challenge or error page served with a 200.
	ErrNotJSON = errors.New("incident: response was not JSON")

	// ErrUpstream is a transient upstream failure: timeouts, 5xx, connection
	// resets. Safe to retry with backoff.
	ErrUpstream = errors.New("incident: upstream request failed")

	// ErrBadRequest means the upstream rejected our parameters. It is never
	// retried: the request is wrong, not unlucky.
	ErrBadRequest = errors.New("incident: upstream rejected the request")

	// ErrWrongDataset means the response decoded correctly but describes a
	// different corpus than the one configured — the classic symptom of a base
	// URL that lost a path prefix and now serves another site's data at 200.
	ErrWrongDataset = errors.New("incident: response is from a different dataset")

	// ErrSchemaDrift means the payload parsed but failed a structural
	// assertion, so its contents cannot be trusted.
	ErrSchemaDrift = errors.New("incident: upstream schema assertion failed")
)
