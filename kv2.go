// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to interact with basic kv2 engines
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
	"path"
)

// KV2Secret is a secret from a KV2 engine
type KV2Secret struct {
	Metadata struct {
		// CreatedTime is when this secret was created
		CreatedTime string `json:"created_time"`

		// DeletionTime is when this secret was destroyed
		DeletionTime string `json:"deletion_time"`

		// Destroyed denotes if this secret was destroyed or not
		Destroyed bool `json:"destroyed"`

		// Version is the current version (revision) of this secret
		Version int `json:"version"`
	} `json:"metadata"`

	// Data contains the data that makes up this secret
	Data map[string]interface{} `json:"data"`
}

//underlyingKV2SecretResponse is the raw response from vault
type underlyingKV2SecretResponse struct {
	Data KV2Secret `json:"data"`
}

// GetKV2Secret returns a KV2 Secret.
//
//  // To get the path `deploy/my/cool/secret`
//  c.GetKV2Secret("deploy", "my/cool/secret")
func (c *Client) GetKV2Secret(ctx context.Context, engine, keyPath string) (*KV2Secret, error) {
	var resp underlyingKV2SecretResponse
	err := c.doRequest(ctx, http.MethodGet, path.Join(engine, "data", keyPath), nil, &resp)
	return &resp.Data, err
}

// CreateKV2Secret creates a new KV2Secret or updates it if it already exists.
func (c *Client) CreateKV2Secret(ctx context.Context, engine, keyPath string,
	secretData map[string]interface{}) error {
	return c.doRequest(ctx, http.MethodPost, path.Join(engine, "data", keyPath), map[string]interface{}{
		"data": secretData,
	}, nil)
}

// UpdateKV2Secret is an alias to CreateKV2Secret
func (c *Client) UpdateKV2Secret(ctx context.Context, engine, keyPath string,
	secretData map[string]interface{}) error {
	return c.CreateKV2Secret(ctx, engine, keyPath, secretData)
}
