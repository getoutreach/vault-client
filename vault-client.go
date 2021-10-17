// Copyright 2021 Outreach Corporation. All Rights Reserved.

// Description: This file is the entrypoint for the vault-client library.

package vault_client //nolint:revive // Why: This nolint is here just in case your project name contains any of [-_].

import (
	"bytes"
	"context"
	"encoding/json" // Client is a Vault client
	"io"
	"net/http"
	"path"

	"github.com/pkg/errors"
)

type Client struct {
	opts *Options
}

func New(optFns ...Opts) *Client {
	opts := &Options{}
	for _, optFn := range optFns {
		optFn(opts)
	}

	return &Client{opts}
}

// doRequest sends a request
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body, resp interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return errors.Wrap(err, "failed to serialize request into json")
		}

		bodyReader = bytes.NewReader(b)
	}

	hResp, err := http.NewRequestWithContext(ctx, method, c.opts.Host+path.Join("/v1/", endpoint), bodyReader)
	if err != nil {
		return errors.Wrap(err, "failed to create rquest")
	}
	// TODO(jaredallard): do response code checking logic here
	defer hResp.Body.Close()

	if err := json.NewDecoder(hResp.Body).Decode(&resp); err != nil {
		return errors.Wrap(err, "failed to decode response")
	}

	return nil
}
