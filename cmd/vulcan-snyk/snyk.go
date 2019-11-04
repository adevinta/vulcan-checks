package main

type SnykResponse struct {
	Vulnerabilities []SnykVulnerability `json:"vulnerabilities"`
}

type SnykVulnerability struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	ModuleName  string          `json:"moduleName"`
	PackageName string          `json:"PackageName"`
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
