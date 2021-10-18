// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"time"

	"github.com/getoutreach/gobox/pkg/cfg"
)

var _ AuthMethod = &TokenAuthMethod{}

// TokenAuthMethod implements a AuthMethod backed by a static authentication token
type TokenAuthMethod struct {
	token cfg.SecretData
}

// NewTokenAuthMethod returns a new TokenAuthMethod with the given token
func NewTokenAuthMethod(token cfg.SecretData) *TokenAuthMethod {
	return &TokenAuthMethod{token}
}

// GetToken returns the static token while implementing AuthMethod.GetToken()
func (a *TokenAuthMethod) GetToken(ctx context.Context) (cfg.SecretData, time.Time, error) {
	return a.token, time.Time{}, nil
}
