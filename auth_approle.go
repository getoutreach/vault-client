package vault_client //nolint:revive // Why: We're using - in the name

import "github.com/getoutreach/gobox/pkg/cfg"

var _ AuthMethod = &ApproleAuthMethod{}

// ApproleAuthMethod implements a AuthMethod backed by an approle
type ApproleAuthMethod struct {
	roleID   cfg.SecretData
	secretID cfg.SecretData
}

// NewApproleAuthMethod returns a new ApproleAuthMethod based on the provided
// roleID and secretID.
func NewApproleAuthMethod(roleID, secretID cfg.SecretData) *ApproleAuthMethod {
	return &ApproleAuthMethod{
		roleID:   roleID,
		secretID: secretID,
	}
}

// GetToken returns a token for the current approle
func (a *ApproleAuthMethod) GetToken() (string, error) {
	return "", nil
}
