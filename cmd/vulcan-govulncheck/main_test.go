// Copyright 2024 Adevinta
package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFindGoModules(t *testing.T) {
	tests := []struct {
		name       string
		base       string
		want       []string
		wantNilErr bool
	}{
		{
			name:       "some",
			base:       "testdata",
			want:       []string{"testdata", "testdata/sub1", "testdata/sub3"},
			wantNilErr: true,
		},
		{
			name:       "none",
			base:       "testdata/sub2",
			want:       nil,
			wantNilErr: true,
		},
		{
			name:       "invalid",
			base:       "invalid",
			want:       nil,
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirs, err := findGoModules(tt.base)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, dirs); diff != "" {
				t.Errorf("unexpected directory list (-want +got):\n%v", diff)
			}
		})
	}
}
