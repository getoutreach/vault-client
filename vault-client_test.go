// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"testing"

	"github.com/getoutreach/vault-client/pkg/vaulttest"
)

// createTestVaultSever creates a Vault server and returns a
// client hooked up to use it. Call the returned function to cleanup.
func createTestVaultServer(t *testing.T, leaveUninitialized bool) (cli *Client, cleanupFn func()) {
	t.Helper()

	host, token, cleanup := vaulttest.NewInMemoryServer(t, leaveUninitialized)
	return New(WithAddress(host), WithTokenAuth(token)), cleanup
}

func TestClient_Failure(t *testing.T) {
	vc, cleanup := createTestVaultServer(t, false)
	defer cleanup()

	_, err := vc.LookupToken(context.Background(), "fake-token")
	if err == nil {
		t.Error("expected invalid token lookup to fail")
	}
}
