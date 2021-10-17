package vault_client //nolint:revive // Why: We're using - in the name

// Options is the options used by the New() client function
type Options struct {
	am AuthMethod

	// Host is the host of the Vault instance
	Host string
}

// AuthMethod is an authentication method that can be used
// by a Vault client.
type Opts func(*Options)

// FromEnv reads configuration from environment variables
// and returns an Options based off of the values
func FromEnv(opts *Options) {
	// TODO(jaredallard): Implement
	return
}
