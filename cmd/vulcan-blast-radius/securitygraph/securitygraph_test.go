/*
Copyright 2022 Adevinta
*/
// Package securitygraph provides a client to interact with the Intel API of the
// Security Graph.
package securitygraph

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestIntelAPIClient_BlastRadius(t *testing.T) {
	tests := []struct {
		name     string
		intelAPI func(t *testing.T) http.HandlerFunc
		req      BlastRadiusRequest
		want     BlastRadiusResponse
		wantErr  error
	}{
		{
			name: "Happy path",
			req: BlastRadiusRequest{
				AssetIdentifier: "example.com",
				AssetType:       "Hostname",
			},
			intelAPI: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Query().Get("asset_identifier") != "example.com" {
						t.Fatalf("got asset_identifier: %s, want: example.com", r.URL.Query().Get("asset_identifier"))
					}
					if r.URL.Query().Get("asset_type") != "Hostname" {
						t.Fatalf("got asset_identifier: %s, want: Hostname", r.URL.Query().Get("asset_type"))
					}
					w.WriteHeader(http.StatusOK)
					resp := BlastRadiusResponse{
						Score:    1.0,
						Metadata: "metadata",
					}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Fatalf("error encoding response: %v", err)
					}
				}
			},
			want: BlastRadiusResponse{
				Score:    1.0,
				Metadata: "metadata",
			},
		},

		{
			name: "Returns ErrAssetDoesNoExist",
			req: BlastRadiusRequest{
				AssetIdentifier: "example.com",
				AssetType:       "Hostname",
			},
			intelAPI: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: ErrAssetDoesNotExist,
		},
		{
			name: "Return ErrNotEnoughInfo",
			req: BlastRadiusRequest{
				AssetIdentifier: "example.com",
				AssetType:       "Hostname",
			},
			intelAPI: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnprocessableEntity)
				}
			},
			wantErr: ErrNotEnoughInfo,
		},
		{
			name: "Return HttpStatusError without message",
			req:  BlastRadiusRequest{},
			intelAPI: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadGateway)
				}
			},
			wantErr: HttpStatusError{
				Status: http.StatusBadGateway,
			},
		},
		{
			name: "Return HttpStatusError with message",
			req:  BlastRadiusRequest{},
			intelAPI: func(t *testing.T) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					resp := struct {
						Msg string `json:"msg"`
					}{Msg: "message"}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Fatalf("error encoding response: %v", err)
					}
				}
			},
			wantErr: HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    "message",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.intelAPI(t)
			server := httptest.NewServer(handler)
			defer server.Close()
			u, _ := url.Parse(server.URL)
			i := &IntelAPIClient{
				c:        *http.DefaultClient,
				endpoint: u,
			}
			got, err := i.BlastRadius(tt.req)
			if err != nil {
				if tt.wantErr == nil {
					t.Errorf("IntelAPIClient.BlastRadius() error = %+v, wantErr %+v", err, tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("IntelAPIClient.BlastRadius() error = %+v, wantErr %+v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IntelAPIClient.BlastRadius() = %v, want %v", got, tt.want)
			}
		})
	}
}
