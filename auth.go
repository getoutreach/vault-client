// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to interact with basic /auth endpoints
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"time"

	"github.com/getoutreach/gobox/pkg/cfg"
)

// AuthMethod is an authentication method that can be used
// by a Vault client.
type AuthMethod interface {
	// GetToken returns the token to use when talking to Vault
	GetToken(ctx context.Context) (token cfg.SecretData, expiresAt time.Time, err error)

	// Options provides the current client options, useful for auth methods
	// that need an underlying vault client to function.
	Options(*Options)
}
