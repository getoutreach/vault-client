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
			c, cleanup := createTestVaultServer(t)
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
