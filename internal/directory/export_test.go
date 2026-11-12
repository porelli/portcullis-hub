package directory

import (
	"context"
	"time"
)

// DesiredFromLLDAP runs Desired against the current LLDAP state (tests).
func (s *Service) DesiredFromLLDAP(ctx context.Context, cfg *Config, now time.Time) (map[string]map[string]bool, error) {
	sn, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	return s.Desired(cfg, sn, now), nil
}

// ValidFieldName exposes validFieldName (tests).
func ValidFieldName(name string) bool { return validFieldName(name) }

// SetSettleTimeoutForTest shortens Settle's wait; the returned func puts
// it back.
func SetSettleTimeoutForTest(d time.Duration) func() {
	old := settleTimeout
	settleTimeout = d
	return func() { settleTimeout = old }
}

// SetSettleEvalForTest makes s's Settle runs call f instead of Evaluate
// (f gets Evaluate to call through).
// A function, not a method: the protected-account parity test lists
// every Service method.
func SetSettleEvalForTest(s *Service, f func(ctx context.Context, now time.Time, eval func(context.Context, time.Time) (*EvalReport, error)) (*EvalReport, error)) {
	s.settleEval = func(ctx context.Context, now time.Time) (*EvalReport, error) { return f(ctx, now, s.Evaluate) }
}

// SetAfterGateForTest makes s's mutations call f between gate and the
// action (a change made meanwhile, e.g. a promotion).
func SetAfterGateForTest(s *Service, f func()) { s.afterGate = f }
