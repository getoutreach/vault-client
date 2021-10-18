package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
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

		// we create a client with no authentication
		c: New(),
	}
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
