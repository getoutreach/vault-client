// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: Stores functions/types for options on the Vault client
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"os" // Options is the options used by the New() client function

	"github.com/getoutreach/gobox/pkg/cfg"
	"github.com/imdario/mergo"
)

// Options are options associated with a Vault client
type Options struct {
	// am is the auth method to use for this client, this is used
	// by the auth_transport to transparently/automatically refresh
	// authentication
	am AuthMethod

	// Host is the host of the Vault instance
	Host string
}

// Opts is an functional option for use with New()
type Opts func(*Options)

// WithEnv reads configuration from environment variables
// and returns an Options based off of the values
func WithEnv(opts *Options) {
	if roleID, ok := os.LookupEnv("VAULT_ROLE_ID"); ok {
		WithApproleAuth(cfg.SecretData(roleID), cfg.SecretData(os.Getenv("VAULT_SECRET_ID")))(opts)
	}

	if host, ok := os.LookupEnv("VAULT_ADDR"); ok {
		WithAddress(host)(opts)
	}

	if token, ok := os.LookupEnv("VAULT_TOKEN"); ok {
		WithTokenAuth(cfg.SecretData(token))(opts)
	}
}

// WithApproleAuth sets up approle authentication on a Client
func WithApproleAuth(roleID, secretID cfg.SecretData) Opts {
	return func(opts *Options) {
		opts.am = NewApproleAuthMethod(roleID, secretID)
	}
}

// WithTokenAuth sets up token authentication on a Client
func WithTokenAuth(token cfg.SecretData) Opts {
	return func(opts *Options) {
		opts.am = NewTokenAuthMethod(token)
	}
}

// WithTokenFileAuth sets up token file auth on a Client
func WithTokenFileAuth(path *string) Opts {
	return func(opts *Options) {
		opts.am = NewTokenFileAuthMethod(path)
	}
}

// WithAddress sets the host to use when talking to Vault on a Client
func WithAddress(hostname string) Opts {
	return func(opts *Options) {
		opts.Host = hostname
	}
}

// WithOptions combines a provided options with the client's
func WithOptions(oldO *Options) Opts {
	return func(newO *Options) {
		mergo.MergeWithOverwrite(newO, oldO) //nolint:errcheck // Why: sig doesn't allow
	}
}
