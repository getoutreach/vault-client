package vault_client //nolint:revive // Why: We're using - in the name

// AuthMethod is an authentication method that can be used
// by a Vault client.
type AuthMethod interface {
	// GetToken returns the token to use when talking to Vault
	GetToken() (string, error)
}
