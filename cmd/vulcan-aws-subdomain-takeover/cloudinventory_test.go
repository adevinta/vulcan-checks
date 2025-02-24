/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
)

func TestCloudInventory_IsIPPublicInInventory(t *testing.T) {
	tests := []struct {
		name               string
		endpointTpl        string
		headers            []string
		notFoundBody       string
		ip                 string
		endpointResponse   string
		statusCodeResponse int
		want               bool
		wantErr            error
	}{
		{
			name:               "no headers",
			endpointTpl:        "/{{.IP}}",
			notFoundBody:       "{}",
			ip:                 "1.2.3.4",
			endpointResponse:   "",
			statusCodeResponse: http.StatusOK,
			want:               true,
			wantErr:            nil,
		},
		{
			name:             "wrong headers",
			endpointTpl:      "/{{.IP}}",
			headers:          []string{"Authorization"},
			ip:               "1.2.3.4",
			endpointResponse: "",
			want:             false,
			wantErr:          ErrInvalidHeader,
		},
		{
			name:               "no ip",
			endpointTpl:        "/{{.IP}}",
			headers:            []string{"Authorization: Bearer token"},
			ip:                 "",
			endpointResponse:   "",
			statusCodeResponse: http.StatusBadRequest,
			want:               false,
			wantErr:            ErrResponseError,
		},
		{
			name:               "ip found",
			endpointTpl:        "/{{.IP}}",
			headers:            []string{"Authorization: Bearer token"},
			ip:                 "1.2.3.4",
			endpointResponse:   "{\"ip\": \"1.2.3.4\"\",\n  \"account_id\": \"aws_account\",\n  \"region\": \"aws_region\"}",
			statusCodeResponse: http.StatusOK,
			want:               true,
			wantErr:            nil,
		},
		{
			name:               "ip not found 404",
			endpointTpl:        "/{{.IP}}",
			headers:            []string{"Authorization: Bearer token"},
			ip:                 "1.2.3.4,",
			endpointResponse:   "",
			statusCodeResponse: http.StatusNotFound,
			want:               false,
			wantErr:            nil,
		},
		{
			name:               "ip not found 200",
			endpointTpl:        "/{{.IP}}",
			headers:            []string{"Authorization: Bearer token"},
			notFoundBody:       "{}",
			ip:                 "1.2.3.4,",
			endpointResponse:   "{}",
			statusCodeResponse: http.StatusOK,
			want:               false,
			wantErr:            nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start a local HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				if req.URL.Path != fmt.Sprintf("/%s", tt.ip) {
					t.Errorf("wrong path: got %s, want %s", req.URL.Path, fmt.Sprintf("/%s", tt.ip))
				}
				// Test request parameters
				rw.WriteHeader(tt.statusCodeResponse)
				_, err := rw.Write([]byte(tt.endpointResponse))
				if err != nil {
					t.Fatal(err)
				}
			}))
			// Close the server when test finishes
			defer server.Close()

			tpl, err := template.New("isInInventory").Parse(fmt.Sprintf("%s%s", server.URL, tt.endpointTpl))
			if err != nil {
				t.Errorf("parsing endpoint template: %v", err)
			}

			ci := &CloudInventory{
				client:       server.Client(),
				endpointTpl:  tpl,
				headers:      tt.headers,
				notFoundBody: tt.notFoundBody,
			}
			got, err := ci.IsIPPublicInInventory(context.Background(), tt.ip)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("unexpected error: got: %v, want: %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("unnexpected response: want %v, got = %v", tt.want, got)
			}
		})
	}
}
