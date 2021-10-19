// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Package vaulttest implements an easy way to spin up
// a test vault instance.
package vaulttest

import (
	"testing"

	"github.com/getoutreach/gobox/pkg/cfg"
	"github.com/hashicorp/vault/builtin/credential/approle"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

// NewInMemoryServer creates a new in-memory server with expected configuration
// e.g. approles being enabled.
func NewInMemoryServer(t *testing.T, leaveUninitialized bool) (host string, token cfg.SecretData, cleanup func()) {
	t.Helper()

	conf := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	}

	var rootToken string
	var core *vault.Core
	if leaveUninitialized {
		core = vault.TestCoreWithConfig(t, conf)
	} else {
		core, _, rootToken = vault.TestCoreUnsealedWithConfig(t, conf)
		vault.TestWaitActive(t, core)
	}

	ln, addr := vaulthttp.TestServer(t, core)
	return addr, cfg.SecretData(rootToken), func() {
		ln.Close()
	}
}
