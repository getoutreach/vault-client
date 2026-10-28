// Copyright 2023 Outreach Corporation. All Rights Reserved.

// Description: tests for checking and ensuring a Vault login
package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

// isolateEnv gives a test an empty home directory, none of the variables
// that choose a token or a headless environment, and a PATH with no
// programs in it, so that the test can't use the developer's own Vault
// login and a run of the vault CLI fails. It returns the home directory.
func isolateEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	for _, k := range []string{"VAULT_TOKEN", "VAULT_ROLE_ID", "CI"} {
		t.Setenv(k, "")
	}
	return home
}

// expiresIn returns the time d from now, as Vault writes an expire_time.
func expiresIn(d time.Duration) string {
	return time.Now().Add(d).UTC().Format(time.RFC3339Nano)
}

// found is the response to a lookup of a valid token with the given
// expire_time, which is nil for a token that never expires.
func found(token string, expireTime any) (status int, body any) {
	return http.StatusOK, map[string]any{"data": map[string]any{"id": token, "expire_time": expireTime}}
}

// denied is Vault's response to a lookup of an expired or unknown token.
func denied() (status int, body any) {
	return http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}}
}

// acceptOnly answers a lookup of the token want like found, and any other
// token like denied.
func acceptOnly(want string, expireTime any) func(string) (int, any) {
	return func(token string) (int, any) {
		if token != want {
			return denied()
		}
		return found(token, expireTime)
	}
}

// lookupServer serves Vault's token lookup-self endpoint. A request is
// answered with the status and body that respond returns for the token it
// carries, and counted.
func lookupServer(t *testing.T, respond func(token string) (status int, body any)) (url string, requests *atomic.Int32) {
	t.Helper()
	requests = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, r.Method, http.MethodPost)
		assert.Equal(t, r.URL.Path, "/v1/auth/token/lookup-self")

		status, body := respond(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.WriteHeader(status)
		assert.NilError(t, json.NewEncoder(w).Encode(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, requests
}

// TestIsLoggedIn_ValidToken also confirms an address that ends in a slash,
// like DevelopmentAddress, works: the server fails a request for "//v1/...".
func TestIsLoggedIn_ValidToken(t *testing.T) {
	isolateEnv(t)
	t.Setenv("VAULT_TOKEN", "s.valid")
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	url, _ := lookupServer(t, acceptOnly("s.valid", expires.Format(time.RFC3339Nano)))

	token, expiresAt, err := IsLoggedIn(context.Background(), url+"/")
	assert.NilError(t, err)
	assert.Equal(t, string(token), "s.valid")
	assert.Assert(t, expiresAt.Equal(expires), "got %s, want %s", expiresAt, expires)
}

// TestIsLoggedIn_TokenSource confirms the token is VAULT_TOKEN, and else the
// token file, like the vault CLI's.
func TestIsLoggedIn_TokenSource(t *testing.T) {
	home := isolateEnv(t)
	url, _ := lookupServer(t, func(token string) (int, any) { return found(token, expiresIn(time.Hour)) })
	assert.NilError(t, os.WriteFile(filepath.Join(home, tokenFileName), []byte("s.from-file\n"), 0o600))

	token, _, err := IsLoggedIn(context.Background(), url)
	assert.NilError(t, err)
	assert.Equal(t, string(token), "s.from-file", "the newline in the file is trimmed")

	t.Setenv("VAULT_TOKEN", "s.from-env")
	token, _, err = IsLoggedIn(context.Background(), url)
	assert.NilError(t, err)
	assert.Equal(t, string(token), "s.from-env")
}

func TestIsLoggedIn_NoToken(t *testing.T) {
	isolateEnv(t)
	url, requests := lookupServer(t, acceptOnly("unused", expiresIn(time.Hour)))

	token, _, err := IsLoggedIn(context.Background(), url)
	assert.NilError(t, err)
	assert.Assert(t, token == nil)
	assert.Equal(t, requests.Load(), int32(0), "there is nothing to look up")
}

func TestIsLoggedIn_RejectedToken(t *testing.T) {
	isolateEnv(t)
	t.Setenv("VAULT_TOKEN", "s.expired")
	url, requests := lookupServer(t, acceptOnly("s.other", expiresIn(time.Hour)))

	token, _, err := IsLoggedIn(context.Background(), url)
	assert.NilError(t, err, "a token that Vault rejects is not logged in, not an error")
	assert.Assert(t, token == nil)
	assert.Equal(t, requests.Load(), int32(1))
}

func TestIsLoggedIn_ServerError(t *testing.T) {
	isolateEnv(t)
	t.Setenv("VAULT_TOKEN", "s.valid")
	url, _ := lookupServer(t, func(string) (int, any) {
		return http.StatusInternalServerError, map[string]any{"errors": []string{"vault is on fire"}}
	})

	_, _, err := IsLoggedIn(context.Background(), url)
	assert.ErrorContains(t, err, "vault is on fire")
}

// TestEnsureLoggedIn_NoLoginNeeded confirms a valid token is returned without
// running the vault CLI (there is none on PATH), including a token that
// never expires.
func TestEnsureLoggedIn_NoLoginNeeded(t *testing.T) {
	for _, tt := range []struct {
		name       string
		expireTime any
		wantZero   bool
	}{
		{name: "expires", expireTime: expiresIn(time.Hour)},
		{name: "never expires", expireTime: nil, wantZero: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			isolateEnv(t)
			t.Setenv("VAULT_TOKEN", "s.valid")
			url, _ := lookupServer(t, acceptOnly("s.valid", tt.expireTime))

			token, expiresAt, err := EnsureLoggedIn(context.Background(), url, OidcAuthMethod, 5*time.Minute)
			assert.NilError(t, err)
			assert.Equal(t, string(token), "s.valid")
			assert.Equal(t, expiresAt.IsZero(), tt.wantZero)
		})
	}
}

// TestEnsureLoggedIn_Headless confirms a needed login is an ErrHeadless
// error, and not an attempt at one, when there is an AppRole or CI.
func TestEnsureLoggedIn_Headless(t *testing.T) {
	for envName, env := range map[string][2]string{
		"approle": {"VAULT_ROLE_ID", "role"},
		"ci":      {"CI", "true"},
	} {
		for _, tt := range []struct {
			name      string
			token     string        // VAULT_TOKEN, if not empty
			expiresIn time.Duration // How long Vault says the token has left, or 0 if it rejects the token
		}{
			{name: "no token"},
			{name: "expired token", token: "s.t"},
			{name: "too little time left", token: "s.t", expiresIn: time.Minute},
		} {
			t.Run(envName+"/"+tt.name, func(t *testing.T) {
				isolateEnv(t)
				t.Setenv(env[0], env[1])
				t.Setenv("VAULT_TOKEN", tt.token)
				url, _ := lookupServer(t, func(token string) (int, any) {
					if tt.expiresIn == 0 {
						return denied()
					}
					return found(token, expiresIn(tt.expiresIn))
				})

				_, _, err := EnsureLoggedIn(context.Background(), url, OidcAuthMethod, 5*time.Minute)
				assert.ErrorIs(t, err, ErrHeadless)
			})
		}
	}
}

// TestEnsureLoggedIn_LoginRunsVaultCLI confirms a login is the one thing that
// runs the vault CLI (with none on PATH, that is the error), and that CI set
// to anything but true does not stop it.
func TestEnsureLoggedIn_LoginRunsVaultCLI(t *testing.T) {
	for _, ci := range []string{"", "false", "0"} {
		t.Run("CI="+ci, func(t *testing.T) {
			isolateEnv(t)
			t.Setenv("CI", ci)

			// With no token, there is no request to the address.
			_, _, err := EnsureLoggedIn(context.Background(), "https://vault.invalid", OidcAuthMethod, 5*time.Minute)
			assert.ErrorContains(t, err, "failed to run vault login")
		})
	}
}
