// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"testing"
)

func TestClient_CreateKV2Secret_GetKV2Secret(t *testing.T) {
	vc, cleanupFn := createTestVaultServer(t, false)
	defer cleanupFn()

	ctx := context.Background()

	data := map[string]interface{}{
		"hello":      "world",
		"best-anime": "naruto",
	}

	// create the secret engine
	if err := vc.CreateEngine(ctx, "deploy", &CreateEngineOptions{
		Type: "kv",
		Options: map[string]interface{}{
			"version": 2,
		},
	}); err != nil {
		t.Errorf("Failed to create a kv2 engine: CreateEngine() = %v", err)
	}

	// create the secret
	if err := vc.CreateKV2Secret(ctx, "deploy", "hello-world", data); err != nil {
		t.Errorf("Failed to create new kv2 secret: CreateKV2Secret() = %v", err)
		return
	}

	sec, err := vc.GetKV2Secret(ctx, "deploy", "hello-world")
	if err != nil {
		t.Errorf("Failed to get created kv2 secret: GetKV2Secret() = %v", err)
		return
	}

	for k, v := range data {
		fv, ok := sec.Data[k]
		if !ok {
			t.Errorf("Returned kv secret was missing field '%s'", k)
			return
		}

		if fv != v {
			t.Errorf("Returned kv secret was field '%s' didn't have expected value ('%s' != '%s'", k, fv, v)
			return
		}
	}
}
