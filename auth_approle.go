// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
	"path"
	"time"

	"github.com/getoutreach/gobox/pkg/cfg"
)

var _ AuthMethod = &ApproleAuthMethod{}

// ApproleAuthMethod implements a AuthMethod backed by an approle
type ApproleAuthMethod struct {
	c *Client

	roleID   cfg.SecretData
	secretID cfg.SecretData
}

// NewApproleAuthMethod returns a new ApproleAuthMethod based on the provided
// roleID and secretID.
func NewApproleAuthMethod(roleID, secretID cfg.SecretData) *ApproleAuthMethod {
	return &ApproleAuthMethod{
		roleID:   roleID,
		secretID: secretID,
	}
}

func (a *ApproleAuthMethod) Options(o *Options) {
	a.c = New(WithAddress(o.Host))
}

// GetToken returns a token for the current approle
func (a *ApproleAuthMethod) GetToken(ctx context.Context) (cfg.SecretData, time.Time, error) {
	resp, err := a.c.ApproleLogin(ctx, a.roleID, a.secretID)
	if err != nil {
		return "", time.Now(), err
	}

	return resp.Auth.ClientToken,
		time.Now().Add(time.Second * time.Duration(resp.Auth.LeaseDuration)), nil
}

// ApproleLoginResponse is a response returned by ApproleLogin
type ApproleLoginResponse struct {
	Auth struct {
		// LeaseDuration is how long this token lives for in seconds
		LeaseDuration int `json:"lease_duration"`

		// Accessor is an accessor that can be used to lookup this token
		Accessor string `json:"accessor"`

		// ClientToken is the actual token
		ClientToken cfg.SecretData `json:"client_token"`

		// TokenPolicies is a list of policies that are attached to this token
		TokenPolicies []string `json:"token_policies"`
	} `json:"auth"`
}

// ApproleLogin creates a new VAULT_TOKEN using the provided approle credentials
func (c *Client) ApproleLogin(ctx context.Context, roleID, secretID cfg.SecretData) (*ApproleLoginResponse, error) {
	var resp ApproleLoginResponse
	err := c.doRequest(ctx, http.MethodPost, "auth/approle/login", map[string]string{
		"role_id":   string(roleID),
		"secret_id": string(secretID),
	}, &resp)
	return &resp, err
}

// CreateApproleOptions are options to provide to CreateApprole, docs:
// https://www.vaultproject.io/api/auth/approle#parameters
type CreateApproleOptions struct {
	// Name is the name of the approle to create
	Name string `json:"-"`

	TokenTTL      string   `json:"token_ttl,omitempty"`
	TokenMaxTTL   string   `json:"token_max_ttl,omitempty"`
	TokenPolicies []string `json:"token_policies,omitempty"`
	Period        int      `json:"period,omitempty"`
	BindSecretID  bool     `json:"bind_secret_id,omitempty"`
}

// CreateApprole creates a new approle in Vault
func (c *Client) CreateApprole(ctx context.Context, opts *CreateApproleOptions) error {
	return c.doRequest(ctx, http.MethodPost, path.Join("auth/approle/role", opts.Name), opts, nil)
}

// GetApproleRoleID returns the role-id for a given approle
func (c *Client) GetApproleRoleID(ctx context.Context, name string) (cfg.SecretData, error) {
	var resp struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}

	err := c.doRequest(ctx, http.MethodGet, path.Join("auth/approle/role", name, "role-id"), nil, &resp)
	if err != nil {
		return "", err
	}

	return cfg.SecretData(resp.Data.RoleID), nil
}

// CreateApproleSecretIDResponse is a new secret_id created
// by CreateApproleSecretID. See docs here:
// https://www.vaultproject.io/api/auth/approle#sample-response-4
type CreateApproleSecretIDResponse struct {
	SecretIDAccessor string         `json:"secret_id_accessor"`
	SecretID         cfg.SecretData `json:"secret_id"`
	SecretIDTTL      int            `json:"secret_id_ttl"`
}

// CreateApproleSecretID creates a new secret_id for a given approle
func (c *Client) CreateApproleSecretID(ctx context.Context, name string) (*CreateApproleSecretIDResponse, error) {
	resp := struct {
		Data CreateApproleSecretIDResponse `json:"data"`
	}{}

	err := c.doRequest(ctx, http.MethodPost, path.Join("auth/approle/role", name, "secret-id"), nil, &resp)
	if err != nil {
		return nil, err
	}

	return &resp.Data, nil
}
