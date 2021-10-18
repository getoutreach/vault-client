// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"testing"
)

const basicPolicyHCL = `
# Required for test which looks up the token
path "auth/token/lookup" {
		capabilities = ["update"]
}
`

func TestClient_ApproleLogin(t *testing.T) {
	vc, cleanupFn := createTestVaultServer(t, false)
	defer cleanupFn()

	ctx := context.Background()

	if err := vc.CreateAuthMethod(ctx, &CreateAuthMethodOptions{Type: "approle"}); err != nil {
		t.Errorf("Failed to create pre-req auth method: CreateAuthMethod() = %v", err)
		return
	}

	if err := vc.CreatePolicy(ctx, t.Name(), basicPolicyHCL); err != nil {
		t.Errorf("Failed to create pre-req policy: CreatePolicy() = %v", err)
		return
	}

	if err := vc.CreateApprole(ctx, &CreateApproleOptions{Name: t.Name(), TokenPolicies: []string{t.Name()}}); err != nil {
		t.Errorf("Failed to create pre-req approle: CreateApprole() = %v", err)
		return
	}

	roleID, err := vc.GetApproleRoleID(ctx, t.Name())
	if err != nil {
		t.Errorf("Failed to get pre-req approle role-id: GetApproleRoleID() = %v", err)
		return
	}

	secretID, err := vc.CreateApproleSecretID(ctx, t.Name())
	if err != nil {
		t.Errorf("Failed to create pre-req approle secred_id: CreateApproleSecretID() = %v", err)
		return
	}

	approleClient := New(WithOptions(vc.opts), WithApproleAuth(roleID, secretID.SecretID))

	currentToken, _, err := approleClient.opts.am.GetToken(ctx)
	if err != nil {
		t.Errorf("Failed to get token: ApproleAuthMethod.GetToken() = %v", err)
		return
	}

	resp, err := approleClient.LookupToken(ctx, currentToken)
	if err != nil {
		t.Errorf("Failed to lookup issued token: LookupToken() = %v", err)
		return
	}

	if resp.ID == "" {
		t.Error("LookupToken(): expected resp.ID to have a value")
	}
}
