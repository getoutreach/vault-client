// Copyright 2022 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to ensure that the user is logged into vault
package cli //nolint:revive // Why: We're using - in the name
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/jsonpath"

	"github.com/getoutreach/gobox/pkg/box"
)

// EnsureLoggedIn ensures that we are authenticated with Vault and have a valid token
func EnsureLoggedIn(ctx context.Context, log logrus.FieldLogger, b *box.Config) ([]byte, error) {
	// Check if we need to issue a new token
	token, err := IsLoggedIn(ctx, log, b)
	if err != nil {
		return nil, err
	} else if token == nil {
		// We did, so issue a new token using our authentication method
		//nolint:gosec // Why: passing in the auth method and vault address
		output, err := exec.CommandContext(ctx, "sh", "-c",
			fmt.Sprintf("vault login -format json -method %s -address %s 2>/dev/null",
				b.DeveloperEnvironmentConfig.VaultConfig.AuthMethod,
				b.DeveloperEnvironmentConfig.VaultConfig.Address)).Output()
		if err != nil {
			return nil, errors.Wrap(err, "failed to run vault login")
		}
		newToken, err := cmdOutputToToken(output, "{$.auth.client_token}")
		return newToken, errors.Wrap(err, "vault output token jsonpath failed")
	}
	return token, nil
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

// IsLoggedIn returns a valid token if auth lease is not expired
func IsLoggedIn(ctx context.Context, log logrus.FieldLogger, b *box.Config) ([]byte, error) {
	//nolint:gosec // Why: Passing in the vault address
	output, err := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf("vault token lookup -format json -address %s",
			b.DeveloperEnvironmentConfig.VaultConfig.Address)).CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "permission denied") {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to lookup vault token")
	}

	expire, err := cmdOutputToToken(output, "{$.data.expire_time}")
	if err != nil {
		return nil, errors.Wrap(err, "failed to vault output expire_time jsonpath")
	}

	expireTime, err := time.Parse(time.RFC3339Nano, string(expire))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse expire_time")
	}

	log.Infof("Token expires in %s (expire_time:%q)", time.Until(expireTime).Truncate(time.Second), expireTime)

	token, err := cmdOutputToToken(output, "{$.data.id}")
	return token, errors.Wrap(err, "failed to vault output token jsonpath")
}
