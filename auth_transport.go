// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Implements a http.Transport for authentication
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/getoutreach/gobox/pkg/cfg"
	"github.com/getoutreach/gobox/pkg/trace"
	"github.com/pkg/errors"
)

// transport provides a http.RoundTripper by wrapping an existing
// http.RoundTripper and provides Vault authentication.
type transport struct {
	tr http.RoundTripper
	am AuthMethod

	mu        sync.Mutex
	token     cfg.SecretData
	expiresAt time.Time
}

// New returns a Transport that automatically refreshes Vault authentication
// and includes it.
//
// The provided tr http.RoundTripper should be shared between multiple
// clients to ensure reuse of underlying TCP connections.
//
// The returned Transport's RoundTrip method is safe to be used concurrently.
// nolint:gocritic // Why: We want to ensure the credentials aren't modified
func NewTransport(tr http.RoundTripper, am AuthMethod) http.RoundTripper {
	return &transport{tr: tr, am: am}
}

// RoundTrip implements http.RoundTripper interface.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.Token(req.Context())
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+string(token))
	}
	resp, err := t.tr.RoundTrip(req)
	return resp, err
}

// Token checks the active token expiration and renews if necessary. Token returns
// a valid client token. If renewal fails an error is returned.
func (t *transport) Token(ctx context.Context) (cfg.SecretData, error) {
	ctx = trace.StartCall(ctx, "vault.token_refresh")
	defer trace.EndCall(ctx)

	t.mu.Lock()
	defer t.mu.Unlock()

	// if the token is empty, we always want to refresh, otherwise if we have
	// an expiresAt, we want to check if it's within 5 minutes of now. if so,
	// we want to refresh it
	if t.token == "" || (!t.expiresAt.IsZero() && t.expiresAt.Add(-(time.Minute * 5)).Before(time.Now())) {
		// Token is not set or expired/nearly expired, so refresh
		if err := t.refreshToken(ctx); err != nil {
			return "", errors.Wrap(err, "failed to refresh vault approle")
		}
	}

	return t.token, nil
}

func (t *transport) refreshToken(ctx context.Context) error {
	if t.am == nil {
		return nil
	}

	var err error
	t.token, t.expiresAt, err = t.am.GetToken(ctx)
	return err
}
