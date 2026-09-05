//go:build live

package canary

import (
	"context"
	"testing"
	"time"
)

type canaryCtx = context.Context

func newTimeoutCtx(t *testing.T, d time.Duration) (context.Context, func()) {
	t.Helper()
	return context.WithTimeout(t.Context(), d)
}
