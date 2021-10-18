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

	"github.com/getoutreach/gobox/pkg/log"
	"github.com/getoutreach/gobox/pkg/trace"
	"github.com/pkg/errors"
)

type Client struct {
	opts *Options

	hc *http.Client
}

func New(optFns ...Opts) *Client {
	opts := &Options{}
	for _, optFn := range optFns {
		optFn(opts)
	}

	hc := (*http.DefaultClient)
	if opts.am != nil {
		hc.Transport = NewTransport(http.DefaultTransport, opts.am)
	}

	return &Client{opts, &hc}
}

// ErrorResponse is returned when an error occurs
type ErrorResponse struct {
	// Errors is a list of errors that were encountered when Vault tried
	// to process this request.
	Errors []string `json:"errors"`
}

// doRequest sends a request
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body, resp interface{}) error {
	uri := c.opts.Host + path.Join("/v1/", endpoint)

	ctx = trace.StartCall(ctx, "vault.request", log.F{"vault.uri": uri, "vault.method": method})
	defer trace.EndCall(ctx)

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return errors.Wrap(err, "failed to serialize request into json")
		}

		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, uri, bodyReader)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	hResp, err := c.hc.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to make request")
	}
	defer hResp.Body.Close()

	// TODO(jaredallard): do response code checking logic here
	// also handle errors
	return errors.Wrap(json.NewDecoder(hResp.Body).Decode(&resp), "failed to decode response")
}
