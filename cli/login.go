// Copyright 2022 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to ensure that the user is logged into vault
package cli //nolint:revive // Why: We're using - in the name
import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/jsonpath"

	"github.com/getoutreach/gobox/pkg/box"
)

// EnsureLoggedIn ensures that we are authenticated with Vault and have a valid token
func EnsureLoggedIn(ctx context.Context, log logrus.FieldLogger, b *box.Config) ([]byte, error) {
	// Check if we need to issue a new token
	//nolint:gosec // Why: Passing in the vault address
	output, err := exec.CommandContext(ctx,
		"vault",
		"token",
		"lookup",
		"-format",
		"json",
		"-address",
		b.DeveloperEnvironmentConfig.VaultConfig.Address).
		CombinedOutput()
	if err != nil {
		// We did, so issue a new token using our authentication method
		//nolint:gosec // Why: passing in the auth method and vault address
		cmd := exec.CommandContext(ctx, "vault",
			"login",
			"-format",
			"json",
			"-method",
			b.DeveloperEnvironmentConfig.VaultConfig.AuthMethod,
			"-address", b.DeveloperEnvironmentConfig.VaultConfig.Address,
		)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return nil, errors.Wrap(err, "failed to run vault login")
		}
		token, err := cmdOutputToToken(output)
		return token, errors.Wrap(err, "vault output token jsonpath failed")
	}
	token, err := cmdOutputToToken(output)
	return token, errors.Wrap(err, "vault output token jsonpath failed")
}

// cmdOutputToToken converts vault token lookup and vault token login output to
// just the token id
func cmdOutputToToken(in []byte) ([]byte, error) {
	jp := jsonpath.New("vault-token")
	if err := jp.Parse("{$.data.id}"); err != nil {
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
