/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"strings"
	"testing"
)

func TestCloudInventory_IsIPPublicInInventory(t *testing.T) {
	const script = `
package inventory

import (
	"strings"
	"context"
	"fmt"
)

var ips = " 1.2.3.4 5.6.7.8 "

func Check(ctx context.Context, ip string) (bool, error) {
	if ip == "" {
		return false, fmt.Errorf("no ip provided")
	}
	return strings.Contains(ips, " "+ip+" "), nil
}`

	a := strings.ReplaceAll(script, "\n", "\\n")
	t.Log(a)
	tests := []struct {
		name    string
		script  string
		ip      string
		want    bool
		wantErr bool
	}{
		{
			name:    "no ip",
			ip:      "",
			want:    false,
			wantErr: true,
		},
		{
			name:    "ip found",
			ip:      "1.2.3.4",
			want:    true,
			wantErr: false,
		},
		{
			name:    "ip not found",
			ip:      "1.2.3.6",
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ci, err := NewCloudInventory(script, "inventory.Check")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, err := ci.IsIPPublicInInventory(context.Background(), tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if got != tt.want {
				t.Errorf("unnexpected response: want %v, got = %v", tt.want, got)
			}
		})
	}
}
