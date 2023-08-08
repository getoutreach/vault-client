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
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/jsonpath"

	"github.com/getoutreach/gobox/pkg/box"
)

// EnsureLoggedIn ensures that we are authenticated with Vault and have a valid token,
// returning the token and expiration date.
func EnsureLoggedIn(ctx context.Context, log logrus.FieldLogger, b *box.Config, minTimeRemaining time.Duration) ([]byte, time.Time, error) {
	// Check if we need to issue a new token
	var refresh bool
	token, expiresAt, err := IsLoggedIn(ctx, log, b)
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
		args := []string{"login", "-format", "json", "-method", b.DeveloperEnvironmentConfig.VaultConfig.AuthMethod, "-address", b.DeveloperEnvironmentConfig.VaultConfig.Address}
		_, err := exec.CommandContext(ctx, "vault", args...).Output()
		if err != nil {
			return nil, time.Time{}, errors.Wrap(err, "failed to run vault login")
		}

		// The login above only returns a little info about the token, so re-request info about the token to get full
		// info about expiry/validity.
		token, expiresAt, err = IsLoggedIn(ctx, log, b)
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
	buf := new(bytes.Buffer)
	err := jp.Execute(buf, data)
	return buf.Bytes(), errors.Wrap(err, "jsonpath failed")
}

// IsLoggedIn returns a valid token and expiration time if auth lease is not expired
func IsLoggedIn(ctx context.Context, log logrus.FieldLogger, b *box.Config) ([]byte, time.Time, error) {
	args := []string{"token", "lookup", "-format", "json", "-address", b.DeveloperEnvironmentConfig.VaultConfig.Address}
	output, err := exec.CommandContext(ctx, "vault", args...).CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "permission denied") {
			return nil, time.Time{}, nil
		}
		return nil, time.Time{}, errors.Wrap(err, "failed to lookup vault token")
	}

	token, expireTime, err := parseTokenOutput(output)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, "failed to parse token output")
	}

	log.Infof("Token expires in %s (expire_time:%q)", time.Until(expireTime).Truncate(time.Second), expireTime)
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
