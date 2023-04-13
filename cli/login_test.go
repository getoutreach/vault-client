// Copyright 2023 Outreach Corporation. All Rights Reserved.

// Description: test login token parsing
package cli

import (
	"fmt"
	"testing"

	"gotest.tools/v3/assert"
)

func TestVaultLoginTokenJSONPath(t *testing.T) {
	tests := map[string]struct {
		input    string
		expr     string
		expected string
	}{
		"logged in lookup token test": {
			input: `{
  "request_id": "676169b4-d7f9-d94d-ac94-a16891024d73",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "X4dXerFDLHFCvfP6nR1Qiz9K",
    "creation_time": 1676411158,
    "creation_ttl": 43200,
    "display_name": "oidc-test.test@outreach.io",
    "entity_id": "697e1d36-03ea-86a3-927d-258b15e30ada",
    "expire_time": "2023-02-15T09:45:58.590848523Z",
    "explicit_max_ttl": 0,
    "external_namespace_policies": {},
    "id": "%s",
    "identity_policies": [
      "root-policy"
    ],
    "issue_time": "2023-02-14T21:45:58.59084807Z",
    "meta": {
      "role": "outreach"
    },
    "num_uses": 0,
    "orphan": true,
    "path": "auth/oidc/oidc/callback",
    "policies": [
      "default"
    ],
    "renewable": true,
    "ttl": 40988,
    "type": "service"
  },
  "warnings": null
}`,
			expr:     "{$.data.id}",
			expected: "s.gNhNGm524pfZDJzIOVk4NGaX",
		},
		"not logged in test": {
			input: `{
  "request_id": "da34f027-defd-0d51-6721-3e3d7db3c694",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": null,
  "warnings": null,
  "auth": {
    "client_token": "%s",
    "accessor": "EKduk9KRRDPLDfbczgqJiWxe",
    "policies": [
      "default",
      "dev-policy",
      "root-policy"
    ],
    "token_policies": [
      "default"
    ],
    "identity_policies": [
      "dev-policy",
      "root-policy"
    ],
    "metadata": {
      "role": "outreach"
    },
    "orphan": true,
    "entity_id": "697e1d36-03ea-86a3-927d-258b15e30adf",
    "lease_duration": 43200,
    "renewable": true,
    "mfa_requirement": null
  }
}`,
			expr:     "{$.auth.client_token}",
			expected: "s.gNhNGm524pfZDJzIOVk4NGaX",
		},
	}
	for name, test := range tests {
		actual, err := cmdOutputToToken([]byte(fmt.Sprintf(test.input, test.expected)), test.expr)
		assert.NilError(t, err, name)
		assert.Equal(t, test.expected, string(actual), name)
	}
}
