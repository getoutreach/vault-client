// Copyright 2022 Outreach Corporation. All Rights Reserved.

// Description: This file implements the Provider interface for a passthrough transit,
// which just returns the same string, unmodified. This type of transit provider should
// only ever be used for testing.

package cipher

import (
	"context"

	"github.com/getoutreach/gobox/pkg/log"
)

// PassthroughConfig is a type that gets imported by internal/rsms/config.go to
// require a manual acknowledgement via config to turn this on, as this is should
// never be used in production (even on accident).
type PassthroughConfig struct {
	Enabled bool `yaml:"Enabled"`
}

// MarshalLog implements the log.Marshaler interface for PassthroughConfig.
func (pc *PassthroughConfig) MarshalLog(addField func(key string, value interface{})) {
	addField("Enabled", pc.Enabled)
}

// Passthrough satisfies the Provider interface. This type should only ever be used for
// testing.
type Passthrough struct{}

// NewPassthrough returns a new instance of Passthrough while also warning that it is in
// use, since this is only meant for testing.
func NewPassthrough(ctx context.Context) *Passthrough {
	log.Warn(ctx, "using passthrough as transit, this is insecure and only meant to be used for testing")

	return &Passthrough{}
}

// Encrypt returns the same value passed in the "in" parameter.
func (*Passthrough) Encrypt(_ context.Context, _ string, in []byte) ([]byte, error) {
	return in, nil
}

// Decrypt returns the same value passed in the "in" parameter.
func (*Passthrough) Decrypt(_ context.Context, _ string, in []byte) ([]byte, error) {
	return in, nil
}
