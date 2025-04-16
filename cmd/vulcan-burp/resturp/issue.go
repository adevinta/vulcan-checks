package resturp

type IssueGraphql struct {
	Confidence string    `json:"confidence"`
	Severity   string    `json:"severity"`
	Path       string    `json:"path"`
	IssueType  IssueType `json:"issue_type"`
}

type IssueType struct {
	Name                         string `json:"name"`
	Description                  string `json:"description_html"`
	Remediation                  string `json:"remediation_html"`
	References                   string `json:"references_html"`
	VulnerabilityClassifications string `json:"vulnerability_classifications_html"`
}
