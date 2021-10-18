// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestWithEnv(t *testing.T) {
	vaultAddr := "http://127.0.0.1:1011"

	os.Setenv("VAULT_ADDR", vaultAddr)

	opts := &Options{}
	WithEnv(opts)

	expected := &Options{
		Host: vaultAddr,
	}

	if diff := cmp.Diff(opts, expected, cmpopts.IgnoreUnexported(Options{})); diff != "" {
		t.Errorf("cmp.Diff = %s", diff)
	}
}
