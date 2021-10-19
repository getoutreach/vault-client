// Copyright 2021 Outreach Corporation. All Rights Reserved.
//
// Description: This file is the entrypoint for the vault-client library.
package vault_client //nolint:revive // Why: This nolint is here just in case your project name contains any of [-_].

import (
	"bytes"
	"context"
	"encoding/json" // Client is a Vault client
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/getoutreach/gobox/pkg/log"
	"github.com/getoutreach/gobox/pkg/trace"
	"github.com/pkg/errors"
)

// Client is a Vault client
type Client struct {
	opts *Options

	hc *http.Client
}

// New creates a new Vault client. By default it is non-functional. Most likely
// it will be consumed like so:
//  vault_client.New(vault_client.WithEnv)
func New(optFns ...Opts) *Client {
	opts := &Options{}
	for _, optFn := range optFns {
		optFn(opts)
	}

	hc := (*http.DefaultClient)
	if opts.am != nil {
		// pass the options we created earlier to the AuthMethod
		// so it can create it's own client.
		opts.am.Options(opts)

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
//nolint:funlen // Why: not that important to break out
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

	r, err := c.hc.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to make request")
	}
	defer r.Body.Close()

	// Useful debugging code
	// buf := &bytes.Buffer{}
	// r.Body = io.NopCloser(io.TeeReader(r.Body, buf))
	// defer func(buf *bytes.Buffer) {
	// 	fmt.Printf("\n\n!!!!!!! %s %d response: %s\n\n", endpoint, r.StatusCode, buf.String())
	// }(buf)

	// we're in error territory, read the entire body and try to parse for errors. If nothing is there, then just
	// try to parse the response as normal json and trust the caller know's what it is doing
	if !(r.StatusCode >= 200 && r.StatusCode < 400) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return errors.Wrap(err, "failed to read response")
		}

		var errResp ErrorResponse
		if err := json.Unmarshal(b, &errResp); err == nil && len(errResp.Errors) >= 1 {
			return fmt.Errorf("%v", errResp.Errors)
		}

		// set the body back to the original contents
		// so that we can optimistically try to parse the non-errors response as JSON again
		r.Body = io.NopCloser(bytes.NewReader(b))
	}

	if resp != nil {
		// not an errorresponse, so optimistically try to parse it
		return errors.Wrap(json.NewDecoder(r.Body).Decode(&resp), "failed to decode response")
	}

	return nil
}
