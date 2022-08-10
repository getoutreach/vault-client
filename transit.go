// Copyright 2021 Outreach Corporation. All Rights Reserved.

// Description: Stores functions to interact with basic /transit endpoints

package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// transitEncryptPath returns the path for vault transit encryption using the passed in key
// name.
func (*Client) transitEncryptPath(key string) string {
	return fmt.Sprintf("transit/encrypt/%s", key)
}

// transitEncryptPayload is the request body for the path that TransitEncrypt invokes.
type transitEncryptPayload struct {
	Plaintext string `json:"plaintext"`
}

// transitEncryptResponse is the response body for the path that TransitEncrypt invokes.
type transitEncryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

// TransitEncrypt takes plaintext data to be encrypted and returns the corresponding
// ciphertext.
func (c *Client) TransitEncrypt(ctx context.Context, key string, in []byte) ([]byte, error) {
	payload := transitEncryptPayload{
		Plaintext: base64.StdEncoding.EncodeToString(in),
	}

	var resp transitEncryptResponse
	if err := c.doRequest(ctx, http.MethodPost, c.transitEncryptPath(key), payload, &resp); err != nil {
		return nil, errors.Wrap(err, "do vault encryption")
	}

	return []byte(resp.Data.Ciphertext), nil
}

// transitDecryptPath returns the path for vault transit decryption using the passed in key
// name.
func (*Client) transitDecryptPath(key string) string {
	return fmt.Sprintf("transit/decrypt/%s", key)
}

// decryptSerialize takes in data meant to be sent to Vault to be decrypted and
// serializes it into a format that Vault is expecting.
func (*Client) decryptSerialize(in []byte) map[string]interface{} {
	return map[string]interface{}{
		"ciphertext": string(in),
	}
}

// transitDecryptPayload is the request body for the path that TransitDecrypt invokes.
type transitDecryptPayload struct {
	Ciphertext string `json:"ciphertext"`
}

// transitDecryptResponse is the response body for the path that TransitDecrypt invokes.
type transitDecryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

// TransitDecrypt takes ciphertext data to be decrypted and returns the corresponding
// plaintext.
func (c *Client) TransitDecrypt(ctx context.Context, key string, in []byte) ([]byte, error) {
	payload := transitDecryptPayload{
		Ciphertext: string(in),
	}

	var resp transitDecryptResponse
	if err := c.doRequest(ctx, http.MethodPost, c.transitDecryptPath(key), payload, &resp); err != nil {
		return nil, errors.Wrap(err, "do vault encryption")
	}

	out, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode plaintext")
	}

	return out, nil
}

// batchDecryptSerialize takes in data meant to be sent to Vault to be decrypted and
// serializes it into a format that Vault is expecting.
func (*Client) batchDecryptSerialize(in []byte) map[string]interface{} {
	return map[string]interface{}{
		"batch_input": string(in),
	}
}

// transitBatchDecryptPayload is the request body for the path that TransitBatchDecrypt invokes.
type transitBatchDecryptPayload struct {
	BatchInput []struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"batch_input"`
}

// transitBatchDecryptResponse is the response body for the path that TransitDecrypt invokes.
type transitBatchDecryptResponse struct {
	Data struct {
		BatchResults []struct {
			Plaintext string `json:"plaintext"`
		} `json:"batch_results"`
	} `json:"data"`
}

// TransitBatchDecrypt takes in an array of cyphertext data to be decrypted and returns the corresponding
// array of plaintext
func (c *Client) TransitBatchDecrypt(ctx context.Context, key string, in []string) ([][]byte, error) {
	var payload transitBatchDecryptPayload
	for _, v := range in {
		payload.BatchInput = append(payload.BatchInput, struct {
			Ciphertext string `json:"ciphertext"`
		}{
			Ciphertext: v,
		})
	}

	var resp transitBatchDecryptResponse
	if err := c.doRequest(ctx, http.MethodPost, c.transitDecryptPath(key), payload, &resp); err != nil {
		return nil, errors.Wrap(err, "do vault decryption")
	}

	out := make([][]byte, 0, len(resp.Data.BatchResults))
	for _, result := range resp.Data.BatchResults {
		decoded, err := base64.StdEncoding.DecodeString(result.Plaintext)
		if err != nil {
			return nil, errors.Wrap(err, "base64 decode plaintext")
		}
		out = append(out, decoded)
	}

	return out, nil
}
