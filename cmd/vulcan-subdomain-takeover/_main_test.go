/*
Copyright 2022 Adevinta
*/
package main

import (
	"context"
	"fmt"
	"testing"

	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"

	"github.com/adevinta/vulcan-checks/cmd/vulcan-blast-radius/intel"
)

type intelAPIMock struct {
	blastRadius func(req intel.BlastRadiusRequest) (intel.BlastRadiusResponse, error)
}

func (i *intelAPIMock) BlastRadius(req intel.BlastRadiusRequest) (intel.BlastRadiusResponse, error) {
	return i.blastRadius(req)
}

func TestRun(t *testing.T) {
	type args struct {
		target         string
		assetType      string
		optJSON        string
		state          checkstate.State
		intelAPIClient intelAPI
	}
	tests := []struct {
		name      string
		args      args
		wantVulns []report.Vulnerability
		wantErr   error
	}{
		{
			name: "Happy Path",
			args: args{
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: &intelAPIMock{
					blastRadius: func(req intel.BlastRadiusRequest) (intel.BlastRadiusResponse, error) {
						if req.AssetIdentifier != "example.com" {
							err := fmt.Errorf("expected identifier: %s, got: %s", "example.com", req.AssetIdentifier)
							return intel.BlastRadiusResponse{}, err
						}
						if req.AssetType != "Hostname" {
							err := fmt.Errorf("expected asset type: %s, got: %s", "Hostname", req.AssetType)
							return intel.BlastRadiusResponse{}, err
						}
						resp := intel.BlastRadiusResponse{
							Score:    1.0,
							Metadata: "meta",
						}
						return resp, nil
					},
				},
			},
			wantVulns: []report.Vulnerability{
				{
					Summary:         "Blast Radius: Medium",
					Description:     blastRadiusVuln.Description,
					Details:         "Calculated Blast Radius score: 1.00",
					Labels:          blastRadiusVuln.Labels,
					Recommendations: blastRadiusVuln.Recommendations,
				},
			},
		},

		{
			name: "No Intel API specified",
			args: args{
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: nil,
			},
			wantErr: ErrNoIntelAPIBaseURL,
		},
		{
			name: "Handles ErrAssetDoesNotExist",
			args: args{
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: &intelAPIMock{
					blastRadius: func(req intel.BlastRadiusRequest) (intel.BlastRadiusResponse, error) {
						return intel.BlastRadiusResponse{}, intel.ErrAssetDoesNotExist
					},
				},
			},
			wantVulns: []report.Vulnerability{
				{
					Summary:         "Blast Radius: Unknown",
					Description:     blastRadiusVuln.Description,
					Details:         "There was an error calculating the blast radius: asset does not exist in the Security Graph",
					Labels:          blastRadiusVuln.Labels,
					Recommendations: blastRadiusVuln.Recommendations,
				},
			},
		},
		{
			name: "Handles ErrHttpStatusError",
			args: args{
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: &intelAPIMock{
					blastRadius: func(req intel.BlastRadiusRequest) (intel.BlastRadiusResponse, error) {
						return intel.BlastRadiusResponse{}, intel.HTTPStatusError{
							Status: 500,
							Msg:    "message",
						}
					},
				},
			},
			wantVulns: []report.Vulnerability{
				{
					Summary:         "Blast Radius: Unknown",
					Description:     blastRadiusVuln.Description,
					Details:         "There was an error calculating the blast radius: invalid http status code received from the intel API: 500, details: message",
					Labels:          blastRadiusVuln.Labels,
					Recommendations: blastRadiusVuln.Recommendations,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(context.Background(), tt.args.target, tt.args.assetType, tt.args.optJSON, tt.args.state, tt.args.intelAPIClient)
			if err != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}

			diff := cmp.Diff(tt.args.state.ResultData.Vulnerabilities, tt.wantVulns)
			if diff != "" {
				t.Errorf("got vulns different to want vulns, diff: %s", diff)
			}

		})
	}
}

func TestBrLevel(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		want  string
	}{
		{
			name:  "VeryHigh",
			score: 100,
			want:  "Very High",
		},
		{
			name:  "High",
			score: 10,
			want:  "High",
		},
		{
			name:  "Medium",
			score: 1,
			want:  "Medium",
		},
		{
			name:  "Low",
			score: 0.9,
			want:  "Low",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brLevel(tt.score); got != tt.want {
				t.Errorf("brLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}
