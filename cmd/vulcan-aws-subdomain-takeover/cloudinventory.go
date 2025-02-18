/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

// CloudInventory is a client to interact with the CloudInventory service.
type CloudInventory struct {
	validator func(context.Context, string) (bool, error)
}

// NewCloudInventory creates a new CloudInventory object.
func NewCloudInventory(script string, function string) (*CloudInventory, error) {
	i := interp.New(interp.Options{
		Env: os.Environ(),
	})
	if err := i.Use(stdlib.Symbols); err != nil {
		return nil, err
	}

	_, err := i.Eval(script)
	if err != nil {
		return nil, err
	}
	v, err := i.Eval(function)
	if err != nil {
		return nil, err
	}

	f, ok := v.Interface().(func(context.Context, string) (bool, error))
	if !ok {
		return nil, fmt.Errorf("invalid validator function")
	}

	return &CloudInventory{
		validator: f,
	}, nil
}

// IsIPPublicInInventory checks if an IP is in the CloudInventory.
func (ci *CloudInventory) IsIPPublicInInventory(ctx context.Context, ip string) (bool, error) {
	return ci.validator(ctx, ip)
}
