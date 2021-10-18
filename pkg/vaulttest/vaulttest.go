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
func NewInMemoryServer(t *testing.T) (host string, token cfg.SecretData, cleanup func()) {
	t.Helper()

	core, _, rookToken := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	})
	vault.TestWaitActive(t, core)

	ln, addr := vaulthttp.TestServer(t, core)
	return addr, cfg.SecretData(rookToken), func() {
		ln.Close()
	}
}
