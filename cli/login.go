// Copyright 2022 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to ensure that the user is logged into vault
package cli //nolint:revive // Why: We're using - in the name
import (
	"context"
	"os"
	"os/exec"

	"github.com/getoutreach/gobox/pkg/box"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// EnsureLoggedIn ensures that we are authenticated with Vault and have a valid token
func EnsureLoggedIn(ctx context.Context, log logrus.FieldLogger, b *box.Config) error {
	// Check if we need to issue a new token
	//nolint:gosec // Why: Passing in the vault address
	err := exec.CommandContext(ctx, "vault", "token", "lookup", "-address", b.DeveloperEnvironmentConfig.VaultConfig.Address).Run()
	if err != nil {
		// We did, so issue a new token using our authentication method
		//nolint:gosec // Why: passing in the auth method and vault address
		cmd := exec.CommandContext(ctx, "vault", "login", "-no-print",
			"-method",
			b.DeveloperEnvironmentConfig.VaultConfig.AuthMethod,
			"-address", b.DeveloperEnvironmentConfig.VaultConfig.Address,
		)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run()
		if err != nil {
			return errors.Wrap(err, "failed to run vault login")
		}
	}

	return nil
}
