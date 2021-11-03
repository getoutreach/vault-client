// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to interact with basic /auth/token endpoints
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
	"time"

	"github.com/getoutreach/gobox/pkg/cfg"
)

// TokenAuthMethod implements a AuthMethod backed by a static authentication token
type TokenAuthMethod struct {
	token cfg.SecretData
}

// NewTokenAuthMethod returns a new TokenAuthMethod with the given token
func NewTokenAuthMethod(token cfg.SecretData) *TokenAuthMethod {
	return &TokenAuthMethod{token}
}

// GetToken returns the static token while implementing AuthMethod.GetToken()
func (a *TokenAuthMethod) GetToken(ctx context.Context) (cfg.SecretData, time.Time, error) {
	return a.token, time.Time{}, nil
}

func (*TokenAuthMethod) Options(*Options) {}

// LookupTokenResponse is the response returned by LookupToken, docs:
// https://www.vaultproject.io/api/auth/token#sample-response-2
type LookupTokenResponse struct {
	Accessor         string    `json:"accessor"`
	CreationTime     int       `json:"creation_time"`
	CreationTTL      int       `json:"creation_ttl"`
	DisplayName      string    `json:"display_name"`
	EntityID         string    `json:"entity_id"`
	ExpireTime       time.Time `json:"expire_time"`
	ExplicitMaxTTL   int       `json:"explicit_max_ttl"`
	ID               string    `json:"id"`
	IdentityPolicies []string  `json:"identity_policies"`
	IssueTime        string    `json:"issue_time"`
	Meta             struct {
		Username string `json:"username"`
	} `json:"meta"`
	NumUses   int      `json:"num_uses"`
	Orphan    bool     `json:"orphan"`
	Path      string   `json:"path"`
	Policies  []string `json:"policies"`
	Renewable bool     `json:"renewable"`
	TTL       int      `json:"ttl"`
}

// LookupToken looks up the provided token and returns information about it
func (c *Client) LookupToken(ctx context.Context, token cfg.SecretData) (*LookupTokenResponse, error) {
	req := map[string]string{
		"token": string(token),
	}

	var resp struct {
		Data LookupTokenResponse
	}
	err := c.doRequest(ctx, http.MethodPost, "auth/token/lookup", req, &resp)
	if err != nil {
		return nil, err
	}

	return &resp.Data, nil
}

// LookupCurrentToken lookups the current active token (self) and returns information
// about it.
func (c *Client) LookupCurrentToken(ctx context.Context) (*LookupTokenResponse, error) {
	var resp struct {
		Data LookupTokenResponse
	}
	err := c.doRequest(ctx, http.MethodPost, "auth/token/lookup-self", nil, &resp)
	if err != nil {
		return nil, err
	}

	return &resp.Data, nil
}
