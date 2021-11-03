// Copyright 2021 Outreach Corporation. All Rights Reserved.
package vault_client //nolint:revive // Why: We're using - in the name

import (
	"context"
	"testing"
	"time"

	"github.com/getoutreach/gobox/pkg/differs"
	"github.com/google/go-cmp/cmp"
	"github.com/mitchellh/mapstructure"
)

func TestClient_Health(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]interface{}
		wantErr bool
	}{
		{
			name: "should return basic health",
			args: args{
				ctx: context.Background(),
			},
			want: map[string]interface{}{
				"Sealed":              false,
				"ClusterName":         differs.AnyString(),
				"ClusterID":           differs.AnyString(),
				"Initialized":         true,
				"PerformanceStandby":  false,
				"ReplicationDrMode":   "disabled",
				"ReplicationPerfMode": "",
				"ServerTimeUtc": differs.Customf(func(o interface{}) bool {
					v, ok := o.(int)
					if !ok {
						return false
					}

					ti := time.Unix(int64(v), 0)
					return !ti.IsZero()
				}),
				"Standby": false,
				"Version": differs.AnyString(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, cleanup := createTestVaultServer(t, false)
			defer cleanup()

			oGot, err := c.Health(tt.args.ctx)

			// convert to map[string]interface for cmp.Diff
			got := make(map[string]interface{})
			mapstructure.Decode(oGot, &got)

			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Health() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, differs.Custom()); diff != "" {
				t.Errorf("Client.Health(): %s", diff)
			}
		})
	}
}

func TestClient_Initialize(t *testing.T) {
	vc, cleanupFn := createTestVaultServer(t, true)
	defer cleanupFn()

	ctx := context.Background()

	resp, err := vc.Initialize(ctx, &InitializeOptions{
		SecretShares:    10,
		SecretThreshold: 10,
	})
	if err != nil {
		t.Errorf("Failed to initialize vault: Initialize() = %v", err)
		return
	}

	// convert to map[string]interface for cmp.Diff
	got := make(map[string]interface{})
	mapstructure.Decode(resp, &got)

	want := map[string]interface{}{
		// check that keys is a []string and len(10)
		"Keys": differs.Customf(func(o interface{}) bool {
			v, ok := o.([]string)
			if !ok {
				return false
			}

			return len(v) == 10
		}),
		"RecoveryKeys": differs.Customf(func(o interface{}) bool {
			_, ok := o.([]string)
			return ok
		}),
		"RootToken": differs.AnyString(),
	}

	if diff := cmp.Diff(want, got, differs.Custom()); diff != "" {
		t.Errorf("Initialize(): %s", diff)
		return
	}
}

func TestClient_CreateEngine(t *testing.T) {
	vc, cleanupFn := createTestVaultServer(t, false)
	defer cleanupFn()

	ctx := context.Background()

	// create the secret engine
	if err := vc.CreateEngine(ctx, "deploy", &CreateEngineOptions{
		Type: "kv",
		Options: map[string]interface{}{
			"version": 2,
		},
	}); err != nil {
		t.Errorf("Failed to create a KV2 engine: CreateEngine() = %v", err)
	}
}
