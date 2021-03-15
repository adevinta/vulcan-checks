/*
Copyright 2019 Adevinta
*/

package main

import "time"

type analysis struct {
	Target       string    `json:"target"`
	Utctimestamp time.Time `json:"utctimestamp"`
	Level        string    `json:"level"`
	Compliance   bool      `json:"compliance"`
	Failures     struct {
		Modern       []string `json:"modern"`
		Intermediate []string `json:"intermediate"`
		Old          []string `json:"old"`
		Vulnerable   []string `json:"vulnerable"`
	} `json:"failures"`
	TargetLevel string `json:"target_level"`
}
