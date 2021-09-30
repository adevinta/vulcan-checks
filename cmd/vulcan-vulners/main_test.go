package main

import (
	"fmt"
	"testing"
)

func TestComputeVulnerabilityID(t *testing.T) {
	tt := []struct {
		elements []string
		ok       string
	}{
		{[]string{"a", "b", "c"}, "35a969de4ed33804b2038c76a749746497d576b3ef282a6ad870fab5fa32cedd"},
		{[]string{"a", "c", "b"}, "35a969de4ed33804b2038c76a749746497d576b3ef282a6ad870fab5fa32cedd"},
		{[]string{"c", "b", "a"}, "35a969de4ed33804b2038c76a749746497d576b3ef282a6ad870fab5fa32cedd"},
		{[]string{"a", "b", "d"}, "3598f06f78dd374990d8f93360a9400c29bf2e9ff42ca956c4e2c4ebda42eeb9"},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%s", tc.ok), func(t *testing.T) {
			n := computeVulnerabilityID(tc.elements)
			if tc.ok != n {
				t.Fatalf("expected result to be %s; got %s", tc.ok, n)
			}
		})
	}
}
