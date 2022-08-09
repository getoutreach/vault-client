// Copyright 2022 Outreach Corporation. All Rights Reserved.

// Description: This file defines the Provider interface that all cipher
// integrations that deal with encryption and decryption (transit, basically)
// should implement.

// Package cipher contains interfaces and functions related to encryption
// and decryption.
package cipher

import "context"

// Provider is the interface that cipher providers must adhere to.
type Provider interface {
	Encrypt(ctx context.Context, orgID string, in []byte) ([]byte, error)
	Decrypt(ctx context.Context, orgID string, in []byte) ([]byte, error)
}
