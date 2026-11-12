package keycloak

import "context"

// ImpersonationNoticeAction is the extension's required action that shows
// a person, at their next sign-in, that an administrator signed in as
// them (contract §8.1 "The notice", D45).
const ImpersonationNoticeAction = "portcullis-impersonation-notice"

// RequireImpersonationNotice adds ImpersonationNoticeAction to username's
// required actions (once; the others are kept), as RequirePasskey adds
// its action.
func (c *Client) RequireImpersonationNotice(ctx context.Context, username string) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	u, err := c.importUser(ctx, tok, username)
	if err != nil {
		return err
	}
	return c.addAction(ctx, tok, u, ImpersonationNoticeAction)
}

// RequiredActions are username's Keycloak required actions (a copy;
// ErrUserNotFound when Keycloak doesn't know the user).
func (c *Client) RequiredActions(ctx context.Context, username string) ([]string, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	u, err := c.importUser(ctx, tok, username)
	if err != nil {
		return nil, err
	}
	return append([]string{}, u.RequiredActions...), nil
}

// UserEnabled reports whether username is enabled in Keycloak
// (ErrUserNotFound when Keycloak doesn't know the user; an absent
// "enabled" is false: fail closed).
func (c *Client) UserEnabled(ctx context.Context, username string) (bool, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return false, err
	}
	u, err := c.importUser(ctx, tok, username)
	if err != nil {
		return false, err
	}
	return u.Enabled != nil && *u.Enabled, nil
}
