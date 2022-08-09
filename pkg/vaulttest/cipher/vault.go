// Copyright 2022 Outreach Corporation. All Rights Reserved.

// Description: This file implements the Provider interface for vault transit.

package cipher

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/getoutreach/gobox/pkg/cfg"
	"github.com/getoutreach/services/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// VaultConfig is a type that gets imported by internal/rsms/config.go to aggregate
// Vault-related configuration from the config file passed to the application.
type VaultConfig struct {
	Address  string     `yaml:"Address"`
	RoleID   cfg.Secret `yaml:"RoleID"`
	SecretID cfg.Secret `yaml:"SecretID"`
}

// MarshalLog implements the log.Marshaler interface for VaultConfig.
func (vc *VaultConfig) MarshalLog(addField func(key string, value interface{})) {
	addField("Address", vc.Address)
}

// Vault implements the Service interface as a transit engine for encryption and
// decryption using Vault as a provider.
type Vault struct {
	client *api.Client
}

// NewVault returns a new instance of Vault as a Service provider. This function
// looks for a vault token at either <home_directory><path_separator>.vault_token
// or under the VAULT_TOKEN environment variable, preferring the VAULT_TOKEN
// environment variable if both are set.
func NewVault(ctx context.Context, vc *VaultConfig) (Provider, error) {
	roleID, err := vc.RoleID.Data(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "retrieve role ID from ops vault")
	}

	secretID, err := vc.SecretID.Data(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "retrieve secret ID from ops vault")
	}

	client, err := vault.NewClient(ctx, vault.Config{
		RoleID:    string(roleID),
		SecretID:  secretID,
		VaultAddr: vc.Address,
		LoginPath: "/v1/auth/approle/login",
	})

	if err != nil {
		return nil, errors.Wrap(err, "connect to vault")
	}

	return &Vault{
		client: client,
	}, nil
}

// encryptPath returns the path for vault transit encryption using the orgID as
// the location of the relevant key.
func (*Vault) encryptPath(orgID string) string {
	return fmt.Sprintf("transit/encrypt/rsms_%s", orgID)
}

// encryptSerialize takes in data meant to be sent to Vault to be encrypted and
// serializes it into a format that Vault is expecting.
func (*Vault) encryptSerialize(in []byte) map[string]interface{} {
	return map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(in),
	}
}

// Encrypt takes plaintext data to be encrypted and returns the corresponding
// ciphertext.
func (v *Vault) Encrypt(_ context.Context, orgID string, in []byte) ([]byte, error) {
	res, err := v.client.Logical().Write(v.encryptPath(orgID), v.encryptSerialize(in))
	if err != nil {
		return nil, errors.Wrap(err, "do vault encryption")
	}

	raw, exists := res.Data["ciphertext"]
	if !exists {
		return nil, errors.New("invalid response body format from vault")
	}

	out, ok := raw.(string)
	if !ok {
		return nil, errors.New("invalid ciphertext format from vault")
	}

	return []byte(out), nil
}

// decryptPath returns the path for vault transit decryption using the orgID as
// the location of the relevant key.
func (*Vault) decryptPath(orgID string) string {
	return fmt.Sprintf("transit/decrypt/rsms_%s", orgID)
}

// decryptSerialize takes in data meant to be sent to Vault to be decrypted and
// serializes it into a format that Vault is expecting.
func (*Vault) decryptSerialize(in []byte) map[string]interface{} {
	return map[string]interface{}{
		"ciphertext": string(in),
	}
}

// Decrypt takes ciphertext data to be decrypted and returns the corresponding
// plaintext.
func (v *Vault) Decrypt(_ context.Context, orgID string, in []byte) ([]byte, error) {
	res, err := v.client.Logical().Write(v.decryptPath(orgID), v.decryptSerialize(in))
	if err != nil {
		return nil, errors.Wrap(err, "do vault decryption")
	}

	raw, exists := res.Data["plaintext"]
	if !exists {
		return nil, errors.New("invalid response body format from vault")
	}

	b64, ok := raw.(string)
	if !ok {
		return nil, errors.New("invalid plaintext format from vault")
	}

	out, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode plaintext")
	}

	return out, nil
}
