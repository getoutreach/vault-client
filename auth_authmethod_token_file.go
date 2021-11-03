// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Authentication method for using a token file that stores a Vault token
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getoutreach/gobox/pkg/cfg"
	"github.com/pkg/errors"
)

// defaultFileName is the default file name that stores vault tokens
var defaultFileName = ".vault-token"

// TokenFileAuthMethod implements a AuthMethod backed by a static authentication token
type TokenFileAuthMethod struct {
	tokenFilePath string
}

// NewTokenFileAuthMethod returns a new TokenAuthMethod that uses a file as the backing for
// a TokenAuthMethod. If the file is not provided the default vault token file is used.
//
// Note: The token is re-read from the file on expiration but currently there is mothing in place
// to actually renew the token for you.
func NewTokenFileAuthMethod(file *string) AuthMethod {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Return an empty token auth method
		return &TokenAuthMethod{""}
	}

	// use the default path
	if file == nil {
		joinedPath := filepath.Join(homeDir, defaultFileName)
		file = &joinedPath
	}

	return &TokenFileAuthMethod{*file}
}

// GetToken returns the static token while implementing AuthMethod.GetToken()
func (a *TokenFileAuthMethod) GetToken(ctx context.Context) (cfg.SecretData, time.Time, error) {
	// read the token into memory
	b, err := os.ReadFile(a.tokenFilePath)
	if err != nil {
		return "", time.Time{}, errors.Wrapf(err, "failed to read vault token at '%s'", a.tokenFilePath)
	}

	token := cfg.SecretData(strings.TrimSpace(string(b)))

	// use an intermediate client to lookup the token and return when it expires
	intermediateClient := New(WithTokenAuth(token))
	tokenInfo, err := intermediateClient.LookupCurrentToken(ctx)
	if err != nil {
		// if we failed to lookup the token just disable renewal
		tokenInfo = &LookupTokenResponse{
			ExpireTime: time.Time{},
		}
	} else if !tokenInfo.Renewable {
		// if not renewable, don't return an expiration time
		tokenInfo.ExpireTime = time.Time{}
	}

	return token, tokenInfo.ExpireTime, nil
}

func (*TokenFileAuthMethod) Options(*Options) {}
