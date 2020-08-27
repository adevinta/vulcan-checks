package resturp

type IssueEvent struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Issue Issue  `json:"issue"`
}

type IssueDefinition struct {
	IssueTypeID                  string `json:"issue_type_id"`
	Name                         string `json:"name"`
	Description                  string `json:"description"`
	Remediation                  string `json:"remediation"`
	References                   string `json:"references"`
	VulnerabilityClassifications string `json:"vulnerability_classifications"`
}

type Issue struct {
	Caption      string     `json:"caption"`
	Confidence   string     `json:"confidence"`
	Description  string     `json:"description"`
	Evidence     []Evidence `json:"evidence"`
	InternalData string     `json:"internal_data"`
	Name         string     `json:"name"`
	Origin       string     `json:"origin"`
	Path         string     `json:"path"`
	SerialNumber string     `json:"serial_number"`
	Severity     string     `json:"severity"`
	TypeIndex    int64      `json:"type_index"`
}

type Evidence struct {
	Detail struct {
		BandFlags []string `json:"band_flags"`
		Payload   struct {
			Bytes string `json:"bytes"`
			Flags int64  `json:"flags"`
		} `json:"payload"`
	} `json:"detail"`
	RequestResponse struct {
		Request []struct {
			Data   string `json:"data"`
			Length int64  `json:"length"`
			Type   string `json:"type"`
		} `json:"request"`
		RequestTime string `json:"request_time"`
		Response    []struct {
			Data   string `json:"data"`
			Length int64  `json:"length"`
			Type   string `json:"type"`
		} `json:"response"`
		URL                 string `json:"url"`
		WasRedirectFollowed bool   `json:"was_redirect_followed"`
	} `json:"request_response"`
	Type string `json:"type"`
}
