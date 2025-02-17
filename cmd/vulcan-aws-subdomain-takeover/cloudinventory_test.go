/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
)

func TestCloudInventory_IsIPPublicInInventory(t *testing.T) {
	tests := []struct {
		name               string
		token              string
		endpointTpl        string
		ip                 string
		endpointResponse   string
		statusCodeResponse int
		want               bool
		wantErr            bool
	}{
		{
			name:               "no token",
			token:              "",
			endpointTpl:        "/{{.IP}}",
			ip:                 "1.2.3.4",
			endpointResponse:   "",
			statusCodeResponse: http.StatusUnauthorized,
			want:               false,
			wantErr:            true,
		},
		{
			name:               "no ip",
			token:              "token",
			endpointTpl:        "/{{.IP}}",
			ip:                 "",
			endpointResponse:   "",
			statusCodeResponse: http.StatusBadRequest,
			want:               false,
			wantErr:            true,
		},
		{
			name:               "ip found",
			token:              "token",
			endpointTpl:        "/{{.IP}}",
			ip:                 "1.2.3.4",
			endpointResponse:   "{\"ip\": \"1.2.3.4\"\",\n  \"account_id\": \"aws_account\",\n  \"region\": \"aws_region\"}",
			statusCodeResponse: http.StatusOK,
			want:               true,
			wantErr:            false,
		},
		{
			name:               "ip not found 404",
			token:              "token",
			endpointTpl:        "/{{.IP}}",
			ip:                 "1.2.3.4,",
			endpointResponse:   "",
			statusCodeResponse: http.StatusNotFound,
			want:               false,
			wantErr:            false,
		},
		{
			name:               "ip not found 200",
			token:              "token",
			endpointTpl:        "/{{.IP}}",
			ip:                 "1.2.3.4,",
			endpointResponse:   "{}",
			statusCodeResponse: http.StatusOK,
			want:               false,
			wantErr:            false,
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
				client:      server.Client(),
				token:       tt.token,
				endpointTpl: tpl,
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
