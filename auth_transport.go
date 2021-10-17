package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

// transport provides a http.RoundTripper by wrapping an existing
// http.RoundTripper and provides Vault authentication.
type transport struct {
	tr http.RoundTripper
}

var _ http.RoundTripper = &transport{}

// New returns an Transport using private key. The key is parsed
// and if any errors occur the error is non-nil.
//
// The provided tr http.RoundTripper should be shared between multiple
// clients to ensure reuse of underlying TCP connections.
//
// The returned Transport's RoundTrip method is safe to be used concurrently.
// nolint:gocritic // Why: We want to ensure the credentials aren't modified
func NewTransport(tr http.RoundTripper) http.RoundTripper {
	return &transport{}
}

// RoundTrip implements http.RoundTripper interface.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.Token(req.Context())
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := t.tr.RoundTrip(req)
	return resp, err
}

// Token checks the active token expiration and renews if necessary. Token returns
// a valid client token. If renewal fails an error is returned.
func (t *transport) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.appRole == nil || t.appRole.expiresAt.Add(-time.Minute).Before(time.Now()) {
		// Token is not set or expired/nearly expired, so refresh
		if err := t.refreshToken(ctx); err != nil {
			return "", errors.Wrap(err, "failed to refresh vault approle")
		}
	}

	return t.appRole.token, nil
}

func (t *transport) refreshToken(ctx context.Context) error {
	// call am.GetToken()
	return nil
}
