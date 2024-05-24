// Copyright 2023 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to ensure that the user is logged into vault
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"k8s.io/client-go/util/jsonpath"
)

// const defines constants for the Vault CLI
const (
	// ProductionAddress is the vault address for the producton Vault server
	ProductionAddress = "https://vault.outreach.cloud"

	// DevelopmentAddress is the Vault address for the development Vault server
	DevelopmentAddress = "https://vault-dev.outreach.cloud/"

	// OidcAuthMethod for using the oidc authentication method to obtain a Vault token
	OidcAuthMethod = "oidc"
)

// EnsureLoggedIn ensures that we are authenticated with Vault and have a valid token, returning the token and expiration date.
func EnsureLoggedIn(ctx context.Context, vaultAddress, authMethod string, minTimeRemaining time.Duration) ([]byte, time.Time, error) {
	// Check if we need to issue a new token
	var refresh bool
	token, expiresAt, err := IsLoggedIn(ctx, vaultAddress)
	if err != nil {
		return nil, time.Time{}, err
	}

	if token == nil {
		// No token found
		refresh = true
	} else if time.Until(expiresAt) < minTimeRemaining {
		// Insufficient time remaining, refresh anyway
		refresh = true
	}

	if refresh {
		// Issue a new token using our authentication method
		//nolint:lll // Why: Passing in the vault address and method
		args := []string{"login", "-format", "json", "-method", authMethod, "-address", vaultAddress}
		_, err := exec.CommandContext(ctx, "vault", args...).Output()
		if err != nil {
			var execErr *exec.ExitError
			if errors.As(err, &execErr) {
				return nil, time.Time{}, errors.Wrapf(err, "failed to run vault login: %s", execErr.Stderr)
			}

			return nil, time.Time{}, errors.Wrap(err, "failed to run vault login (no stderr)")
		}

		// The login above only returns a little info about the token, so re-request info about the token to get full
		// info about expiry/validity.
		token, expiresAt, err = IsLoggedIn(ctx, vaultAddress)
		if err != nil {
			return nil, time.Time{}, errors.Wrap(err, "failed to parse token output")
		}
	}

	return token, expiresAt, nil
}

// cmdOutputToToken converts vault token lookup and vault token login output to
// just the token id
func cmdOutputToToken(in []byte, expr string) ([]byte, error) {
	jp := jsonpath.New("vault-token")
	if err := jp.Parse(expr); err != nil {
		return nil, err
	}
	var data interface{}
	if err := json.Unmarshal(in, &data); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err := jp.Execute(&buf, data)
	return buf.Bytes(), errors.Wrapf(err, "failed to execute jsonpath %q", expr)
}

// IsLoggedIn returns a valid token and expiration time if it is not expired
func IsLoggedIn(ctx context.Context, vaultAddress string) ([]byte, time.Time, error) {
	args := []string{"token", "lookup", "-format", "json", "-address", vaultAddress}
	output, err := exec.CommandContext(ctx, "vault", args...).CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "permission denied") {
			return nil, time.Time{}, nil
		}
		return nil, time.Time{}, errors.Wrapf(err, "failed to lookup vault token: %s", output)
	}

	token, expireTime, err := parseTokenOutput(output)
	if err != nil {
		return nil, time.Time{}, errors.Wrapf(err, "failed to parse token output: %s", output)
	}

	log.InfoContext(ctx, "Logged into Vault", "expires", expireTime, "address", vaultAddress)
	return token, expireTime, nil
}

// parseTokenOutput parses the raw output from the vault CLI to get attributes of a token
func parseTokenOutput(output []byte) ([]byte, time.Time, error) {
	expire, err := cmdOutputToToken(output, "{$.data.expire_time}")
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, "failed to vault output expire_time jsonpath")
	}

	expireTime, err := time.Parse(time.RFC3339Nano, string(expire))
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, "failed to parse expire_time")
	}

	token, err := cmdOutputToToken(output, "{$.data.id}")
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, "failed to vault output token jsonpath")
	}

	return token, expireTime, nil
}
