// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewTokenFileAuthMethod(t *testing.T) {
	vc, cleanupFn := createTestVaultServer(t, false)
	defer cleanupFn()

	ctx := context.Background()

	rootToken, _, err := vc.opts.am.GetToken(ctx)
	if err != nil {
		t.Errorf("Failed to get root token: am.GetToken() = %v", err)
		return
	}

	f, err := os.CreateTemp("", "vault-client-root-token-*")
	if err != nil {
		t.Errorf("Failed to create temp file for root-token: os.CreateTemp() = %v", err)
		return
	}
	defer os.Remove(f.Name())

	if _, err = f.Write([]byte(rootToken)); err != nil {
		t.Errorf("Failed to write to temp file for root-token: f.Write() = %v", err)
		return
	}
	f.Close() //nolint:errcheck // Why: best effort

	fileName := f.Name()
	testClient := New(WithAddress(vc.opts.Host), WithTokenFileAuth(&fileName))
	tokenInfo, err := testClient.LookupCurrentToken(ctx)
	if err != nil {
		t.Errorf("Failed to lookup current token: LookupCurrentToken() = %v", err)
		return
	}

	if tokenInfo.ID == "" {
		t.Error("LookupToken(): expected resp.ID to have a value")
		return
	}

	if tokenInfo.ID != string(rootToken) {
		t.Error("LookupToken(): expected resp.ID to equal root-token")
		return
	}
}

func TestNewTokenFileAuthMethodReturnsDefault(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Failed to get current user's homeDir: os.UserHomeDir() = %v", err)
		return
	}

	tokenPath := filepath.Join(homeDir, defaultFileName)

	currentTokenContents, err := os.ReadFile(tokenPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		// if we don't have one then we should create one
		currentTokenContents = []byte("abcdefg")
		if err := os.WriteFile(tokenPath, currentTokenContents, 0600); err != nil {
			t.Errorf("Failed to write user's vault-token: os.WriteFile() = %v", err)
			return
		}
	} else if err != nil {
		t.Errorf("Failed to read current user's vault-token: os.ReadFile() = %v", err)
		return
	}

	token, _, err := NewTokenFileAuthMethod(nil).GetToken(context.Background())
	if err != nil {
		t.Errorf("Failed to read user's vault-token via transport: GetToken() = %v", err)
		return
	}

	if string(token) != strings.TrimSpace(string(currentTokenContents)) {
		t.Errorf("Expected GetToken to return same token as existed in default file, '%s' != '%s'", token, currentTokenContents)
		return
	}
}
