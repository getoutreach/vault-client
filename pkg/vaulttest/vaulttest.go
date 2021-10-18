// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Package vaulttest implements an easy way to spin up
// a test vault instance.
package vaulttest

import (
	"testing"

	"github.com/getoutreach/gobox/pkg/cfg"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
)

// NewInMemoryServer creates a new in-memory server
func NewInMemoryServer(t *testing.T) (host string, token cfg.SecretData, cleanup func()) {
	t.Helper()

	core, _, rootToken := vault.TestCoreUnsealed(t)
	ln, addr := http.TestServer(t, core)
	return addr, cfg.SecretData(rootToken), func() {
		ln.Close()
	}
}
