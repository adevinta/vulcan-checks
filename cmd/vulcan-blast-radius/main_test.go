/*
Copyright 2022 Adevinta
*/
package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-blast-radius/securitygraph"
	report "github.com/adevinta/vulcan-report"
)

type intelAPIMock struct {
	blastRadius func(req securitygraph.BlastRadiusRequest) (securitygraph.BlastRadiusResponse, error)
}

func (i *intelAPIMock) BlastRadius(req securitygraph.BlastRadiusRequest) (securitygraph.BlastRadiusResponse, error) {
	return i.blastRadius(req)
}

func TestRun(t *testing.T) {
	type args struct {
		ctx            context.Context
		target         string
		assetType      string
		optJSON        string
		state          checkstate.State
		intelAPIClient intelAPI
	}
	tests := []struct {
		name      string
		args      args
		env       map[string]string
		wantVulns []report.Vulnerability
		wantErr   error
	}{
		{
			name: "Happy Path",
			args: args{
				ctx:       context.Background(),
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: &intelAPIMock{
					blastRadius: func(req securitygraph.BlastRadiusRequest) (securitygraph.BlastRadiusResponse, error) {
						if req.AssetIdentifier != "example.com" {
							err := fmt.Errorf("expected identifier: %s, got: %s", "example.com", req.AssetIdentifier)
							return securitygraph.BlastRadiusResponse{}, err
						}
						if req.AssetType != "Hostname" {
							err := fmt.Errorf("expected asset type: %s, got: %s", "Hostname", req.AssetType)
							return securitygraph.BlastRadiusResponse{}, err
						}
						resp := securitygraph.BlastRadiusResponse{
							Score:    1.0,
							Metadata: "meta",
						}
						return resp, nil
					},
				},
			},
			wantVulns: []report.Vulnerability{
				{
					Summary:         "Blast Radius Score: 1.00",
					Description:     blastRadiusVuln.Description,
					Details:         "meta",
					Labels:          blastRadiusVuln.Labels,
					Recommendations: blastRadiusVuln.Recommendations,
				},
			},
		},

		{
			name: "No Intel API specified",
			args: args{
				ctx:       context.Background(),
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: nil,
			},
			env:     map[string]string{},
			wantErr: ErrNoIntelAPIBaseURL,
		},
		{
			name: "Handles ErrAssetDoesNotExist",
			args: args{
				ctx:       context.Background(),
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: &intelAPIMock{
					blastRadius: func(req securitygraph.BlastRadiusRequest) (securitygraph.BlastRadiusResponse, error) {
						return securitygraph.BlastRadiusResponse{}, securitygraph.ErrAssetDoesNotExist
					},
				},
			},
			wantVulns: []report.Vulnerability{
				{
					Summary:         "Blast Radius Score: Unknown",
					Description:     blastRadiusVuln.Description,
					Details:         securitygraph.ErrAssetDoesNotExist.Error(),
					Labels:          blastRadiusVuln.Labels,
					Recommendations: blastRadiusVuln.Recommendations,
				},
			},
		},
		{
			name: "Handles ErrAssetDoesNotExist",
			args: args{
				ctx:       context.Background(),
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: &intelAPIMock{
					blastRadius: func(req securitygraph.BlastRadiusRequest) (securitygraph.BlastRadiusResponse, error) {
						return securitygraph.BlastRadiusResponse{}, securitygraph.ErrNotEnoughInfo
					},
				},
			},
			wantVulns: []report.Vulnerability{
				{
					Summary:         "Blast Radius Score: Unknown",
					Description:     blastRadiusVuln.Description,
					Details:         securitygraph.ErrNotEnoughInfo.Error(),
					Labels:          blastRadiusVuln.Labels,
					Recommendations: blastRadiusVuln.Recommendations,
				},
			},
		},
		{
			name: "Handles ErrHttpStatusError",
			args: args{
				ctx:       context.Background(),
				target:    "example.com",
				assetType: "Hostname",
				state: checkstate.State{
					ResultData: &report.ResultData{},
				},
				intelAPIClient: &intelAPIMock{
					blastRadius: func(req securitygraph.BlastRadiusRequest) (securitygraph.BlastRadiusResponse, error) {
						return securitygraph.BlastRadiusResponse{}, securitygraph.HttpStatusError{
							Status: 500,
							Msg:    "message",
						}
					},
				},
			},
			wantVulns: []report.Vulnerability{
				{
					Summary:         "Blast Radius Score: Unknown",
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
			for k, v := range tt.env {
				os.Setenv(k, v)
				defer os.Setenv(k, "")
			}
			err := run(tt.args.ctx, tt.args.target, tt.args.assetType, tt.args.optJSON, tt.args.state, tt.args.intelAPIClient)
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
