// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions to interact with basic /sys/policy endpoints
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"net/http"
	"path"
)

// CreatePolicy creates a new policy
func (c *Client) CreatePolicy(ctx context.Context, name, policy string) error {
	return c.doRequest(ctx, http.MethodPost, path.Join("sys/policy", name), map[string]string{
		"policy": policy,
	}, nil)
}
