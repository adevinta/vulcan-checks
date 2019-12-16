package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type SnykResponse struct {
	Vulnerabilities []SnykVulnerability `json:"vulnerabilities"`
}

type SnykVulnerability struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	PackageName string          `json:"package"`
	Version     string          `json:"version"`
	Language    string          `json:"language"`
	ID          string          `json:"id"`
	Severity    string          `json:"severity"`
	CVSSScore   float32         `json:"cvssScore"`
	Identifiers SnykIdentifiers `json:"identifiers"`
	From        []string        `json:"from"`
	References  []SnykReference `json:"references"`
}

type SnykIdentifiers struct {
	CWE []string `json:"CWE"`
}

type SnykReference struct {
	URL string `json:"url"`
}

type orgsResponse struct {
	Orgs []org `json:"orgs"`
}

type org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func getOrgs() (*orgsResponse, error) {
	buf, err := doRequest("GET", "orgs")
	if err != nil {
		return nil, err
	}

	var orgsResponse orgsResponse
	json.Unmarshal(buf, &orgsResponse)
	if err != nil {
		return nil, err
	}

	return &orgsResponse, nil
}

type projectIssuesResponse struct {
	Issues struct {
		Vulnerabilities []SnykVulnerability `json:"vulnerabilities"`
	} `json:"issues"`
}

func getProjectIssues(orgID, projectID string) (*projectIssuesResponse, error) {
	buf, err := doRequest("POST", fmt.Sprintf("org/%s/project/%s/issues", orgID, projectID))
	if err != nil {
		return nil, err
	}

	var projectIssuesResponse projectIssuesResponse
	json.Unmarshal(buf, &projectIssuesResponse)
	if err != nil {
		return nil, err
	}

	return &projectIssuesResponse, nil
}

type orgProjectsResponse struct {
	Projects []project `json:"projects"`
}

type project struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Origin string `json:"origin"`
}

func getProjects(id string) (*orgProjectsResponse, error) {
	buf, err := doRequest("GET", fmt.Sprintf("org/%s/projects", id))
	if err != nil {
		return nil, err
	}

	var orgProjectsResponse orgProjectsResponse
	json.Unmarshal(buf, &orgProjectsResponse)
	if err != nil {
		return nil, err
	}

	return &orgProjectsResponse, nil
}

const baseURL = "https://snyk.io/api/v1/"

func doRequest(method, path string) ([]byte, error) {
	req, err := http.NewRequest(method, baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	req.Header.Add("Authorization", fmt.Sprintf("token %s", os.Getenv("SNYK_TOKEN")))

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func getSnykRepositoryName(snykProject project, options options) string {
	snykRepositoryName := snykProject.Name
	if snykProject.Origin == `github-enterprise` {
		snykRepositoryName = snykRepositoryName[len(options.BaseURL)+1:]
		i := strings.Index(snykRepositoryName, ":")
		if i >= 0 {
			snykRepositoryName = snykRepositoryName[:i]
		}
	}

	if snykProject.Origin == `cli` {
		i := strings.Index(snykRepositoryName, "/")
		if i >= 0 {
			snykRepositoryName = snykRepositoryName[:i]
		}

		i = strings.Index(snykRepositoryName, ":")
		if i >= 0 {
			snykRepositoryName = snykRepositoryName[:i]
		}
	}
	return snykRepositoryName
}
