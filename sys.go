// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to interact with basic /sys endpoints
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
	"path"
)

// InitializeResponse is the response from Initialize()
type InitializeResponse struct {
	// Keys are the keys returned by the initialization call
	Keys []string `json:"keys"`

	// RecoveryKeys are the recovery keys returned by initialization.
	// These are only present when the underlying Vault configuration is
	// setup to be auto-unsealed.
	RecoveryKeys []string `json:"recovery_keys"`

	// RootToken is the Vault root token returned by the initialization call
	RootToken string `json:"root_token"`
}

// InitializeOptions are the options to be provided to Initialize()
type InitializeOptions struct {
	// SecretShares are how many secret shares to break the unseal key into
	SecretShares int `json:"secret_shares"`

	// SecretThreshold is how many of the secret shares should be provided
	// to be able to unseal the Vault. This must not be more than SecretShares.
	SecretThreshold int `json:"secret_threshold"`

	// RecoveryShares are how many recovery shares to split the recovery key into
	// This is only required when Vault is in autounseal mode.
	RecoveryShares int `json:"recovery_shares,omitempty"`
	// RecoveryThreshold is how many of the recovery shares should be provided for
	// an operation that requires the recovery key.
	RecoveryThreshold int `json:"recovery_threshold,omitempty"`
}

// Initialize initializes a Vault cluster
func (c *Client) Initialize(ctx context.Context, opts *InitializeOptions) (*InitializeResponse, error) {
	var resp InitializeResponse
	if err := c.doRequest(ctx, http.MethodPut, "sys/init", opts, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// HealthResponse is a response returned by Health.
// Docs: https://www.vaultproject.io/api/system/health#sample-response
type HealthResponse struct {
	Initialized         bool   `json:"initialized"`
	Sealed              bool   `json:"sealed"`
	Standby             bool   `json:"standby"`
	PerformanceStandby  bool   `json:"performance_standby"`
	ReplicationPerfMode string `json:"replication_perf_mode"`
	ReplicationDrMode   string `json:"replication_dr_mode"`
	ServerTimeUtc       int    `json:"server_time_utc"`
	Version             string `json:"version"`
	ClusterName         string `json:"cluster_name"`
	ClusterID           string `json:"cluster_id"`
}

// Health returns the current health, or "status", of a Vault cluster
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.doRequest(ctx, http.MethodGet, "sys/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateAuthMethodOptions are options for creating an auth method with CreateAuthMethod
type CreateAuthMethodOptions struct {
	// Path is the path that this auth method should be mounted on.
	// If not set, type is used.
	Path string `json:"-"`

	// Description is an optional description of this auth method, for humans
	Description string `json:"description,omitempty"`

	// Type is the type of auth method to create. Required.
	// Options: https://www.vaultproject.io/api-docs/system/auth#type
	Type string `json:"type,omitempty"`

	// Config is auth method specific options, see: https://www.vaultproject.io/api-docs/system/auth#config
	Config map[string]interface{} `json:"config,omitempty"`
}

// CreateAuthMethod creates a new auth method on the given path
func (c *Client) CreateAuthMethod(ctx context.Context, opts *CreateAuthMethodOptions) error {
	if opts.Path == "" {
		opts.Path = opts.Type
	}
	return c.doRequest(ctx, http.MethodPost, path.Join("sys/auth", opts.Path), opts, nil)
}
