/*
Copyright 2025 Adevinta
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"text/template"
)

type CloudInventory struct {
	client   *http.Client
	token    string
	endpoint string
}

func NewCloudInventory(token string, endpoint string) *CloudInventory {
	return &CloudInventory{
		client:   &http.Client{},
		token:    token,
		endpoint: endpoint,
	}
}

func (ci *CloudInventory) IsIPPublicInInventory(ip string) (bool, error) {
	t, err := template.New("isInInventory").Parse(ci.endpoint)
	if err != nil {
		return false, err
	}
	var tpl bytes.Buffer
	data := struct {
		IP string
	}{
		IP: ip,
	}
	if err = t.Execute(&tpl, data); err != nil {
		return false, err
	}

	req, err := http.NewRequest(http.MethodGet, tpl.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("xc-token", ci.token)
	res, err := ci.client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		if string(resBody) == "{}" {
			return false, nil
		}
		return true, nil
	} else if res.StatusCode == http.StatusNotFound {
		return false, nil
	} else {
		return false, fmt.Errorf("CloudInventory returned %s", res.Status)
	}
}
