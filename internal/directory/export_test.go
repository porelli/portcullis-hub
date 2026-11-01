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
