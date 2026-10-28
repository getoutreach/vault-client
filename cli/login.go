// Copyright 2023 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to ensure that the user is logged into vault
package cli

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/getoutreach/gobox/pkg/cfg"
	vault_client "github.com/getoutreach/vault-client"
	"github.com/pkg/errors"
)

// const defines constants for the Vault CLI
const (
	// ProductionAddress is the vault address for the producton Vault server
	ProductionAddress = "https://vault.outreach.cloud"

	// DevelopmentAddress is the Vault address for the development Vault server
	DevelopmentAddress = "https://vault-dev.outreach.cloud/"

	// OidcAuthMethod for using the oidc authentication method to obtain a Vault token
	OidcAuthMethod = "oidc"

	// tokenFileName is the vault CLI's token file, in the home directory.
	tokenFileName = ".vault-token"
)

// ErrHeadless is returned by EnsureLoggedIn when a login is needed but
// cannot be done, because it needs a person with a browser and this is a
// headless environment (CI, or an AppRole is configured).
var ErrHeadless = errors.New("a vault login is needed, but it needs a browser and this environment is headless " +
	"(VAULT_ROLE_ID or CI is set); log in some other way, for example with AppRole credentials")

// EnsureLoggedIn ensures that we are authenticated with Vault and have a valid token, returning the token and expiration date.
//
// A login runs the vault CLI (for oidc, that opens a browser), so it is for
// people at a workstation. Where that can't work, it is an ErrHeadless error.
func EnsureLoggedIn(ctx context.Context, vaultAddress, authMethod string, minTimeRemaining time.Duration) ([]byte, time.Time, error) {
	// Check if we need to issue a new token: there is none, or it has too little
	// time remaining. A token with no expiration time never expires.
	token, expiresAt, err := IsLoggedIn(ctx, vaultAddress)
	if err != nil {
		return nil, time.Time{}, err
	}
	refresh := token == nil || (!expiresAt.IsZero() && time.Until(expiresAt) < minTimeRemaining)

	if refresh {
		if isHeadless() {
			return nil, time.Time{}, ErrHeadless
		}

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
			return nil, time.Time{}, errors.Wrap(err, "failed to lookup token after login")
		}
	}

	return token, expiresAt, nil
}

// isHeadless returns true if a login that needs a browser cannot be done:
// an AppRole is configured, or this is CI (CircleCI and GitHub Actions set
// CI=true). It deliberately does not look for a terminal, since the oidc
// login does not read from one.
func isHeadless() bool {
	ci, _ := strconv.ParseBool(os.Getenv("CI")) //nolint:errcheck // Why: Unset or not a boolean is not CI.
	return os.Getenv("VAULT_ROLE_ID") != "" || ci
}

// currentToken returns the token that the vault CLI would use: VAULT_TOKEN,
// or else the token file. It returns an empty token if there is neither.
func currentToken() (string, error) {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "failed to find the home directory")
	}
	b, err := os.ReadFile(filepath.Join(home, tokenFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", errors.Wrap(err, "failed to read the vault token file")
	}
	return strings.TrimSpace(string(b)), nil
}

// IsLoggedIn returns a valid token and expiration time if it is not expired.
// The expiration time is the zero time for a token that does not expire. It
// returns no token, and no error, if there is no token or Vault does not
// accept it.
func IsLoggedIn(ctx context.Context, vaultAddress string) ([]byte, time.Time, error) {
	token, err := currentToken()
	if err != nil {
		return nil, time.Time{}, err
	}
	if token == "" {
		return nil, time.Time{}, nil
	}

	client := vault_client.New(
		vault_client.WithAddress(vaultAddress),
		vault_client.WithTokenAuth(cfg.SecretData(token)),
	)
	info, err := client.LookupCurrentToken(ctx)
	if err != nil {
		// Vault says this for a token that is expired or unknown.
		if strings.Contains(err.Error(), "permission denied") {
			return nil, time.Time{}, nil
		}
		return nil, time.Time{}, errors.Wrap(err, "failed to lookup vault token")
	}

	log.InfoContext(ctx, "Logged into Vault", "expires", info.ExpireTime, "address", vaultAddress)
	return []byte(info.ID), info.ExpireTime, nil
}
