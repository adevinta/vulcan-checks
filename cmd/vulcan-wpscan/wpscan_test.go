/*
Copyright 2023 Adevinta
*/

package main

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestRemoveSensitiveLogFormatter(t *testing.T) {
	formatter := &RemoveSensitiveContentFormatter{}

	testCases := []struct {
		name        string
		entry       *logrus.Entry
		expected    string
		expectedErr error
	}{
		{
			name: "NoParamsField",
			entry: &logrus.Entry{
				Data: logrus.Fields{
					"key":  "value",
					"key2": "value2",
				},
			},
			expected:    "time=\"0001-01-01T00:00:00Z\" level=panic key=value key2=value2",
			expectedErr: nil,
		},
		{
			name: "ParamsWithoutApiToken",
			entry: &logrus.Entry{
				Data: logrus.Fields{
					"params": []string{"-W0", "command", "--flag", "value"},
				},
			},
			expected:    "time=\"0001-01-01T00:00:00Z\" level=panic params=\"[-W0 command --flag value]\"",
			expectedErr: nil,
		},
		{
			name: "ParamsWithApiToken",
			entry: &logrus.Entry{
				Data: logrus.Fields{
					"params": []string{"-W0", "command", "--api-token", "sensitive-token", "--flag", "value"},
				},
			},
			expected:    "time=\"0001-01-01T00:00:00Z\" level=panic params=\"[-W0 command --api-token <redacted> --flag value]\"",
			expectedErr: nil,
		},
		{
			name: "ParamsWithApiTokenAtEnd",
			entry: &logrus.Entry{
				Data: logrus.Fields{
					"params": []string{"-W0", "command", "--flag", "value", "--api-token", "sensitive-token"},
				},
			},
			expected:    "time=\"0001-01-01T00:00:00Z\" level=panic params=\"[-W0 command --flag value --api-token <redacted>]\"",
			expectedErr: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			output, err := formatter.Format(testCase.entry)
			if err != testCase.expectedErr {
				t.Errorf("Expected error: %v, but got: %v", testCase.expectedErr, err)
			}

			actual := strings.TrimSpace(string(output))
			if actual != testCase.expected {
				t.Errorf("Expected formatted log entry: %q, but got: %q", testCase.expected, actual)
			}
		})
	}
}
