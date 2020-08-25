package resturp

import "fmt"

// Scan defines the information required by the BURP API to create a scan.
type Scan struct {
	ApplicationLogins  []ApplicationLogin  `json:"application_logins,omitempty"`
	Name               string              `json:"name,omitempty"`
	ResourcePool       string              `json:"resource_pool,omitempty"`
	ScanCallback       *ScanCallback       `json:"scan_callback,omitempty"`
	ScanConfigurations []ScanConfiguration `json:"scan_configurations,omitempty"`
	Scope              *Scope              `json:"scope,omitempty"`
	Urls               []string            `json:"urls"`
}

// ApplicationLogin defines credentials to be used in a scan.
type ApplicationLogin struct {
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`
}

// ScanCallback defines a url to be call when the scan finishes.
type ScanCallback struct {
	URL string `json:"url,omitempty"`
}

// ScanConfiguration defines a named configuration to be used in a scan. The
// configuration must be present in the Burp scan configuration library. The
// type parameter must be set to NamedConfiguration.
type ScanConfiguration struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// Scope defines rules to include or exclude url's
// in a web scan.
type Scope struct {
	Exclude []struct {
		Rule string `json:"rule,omitempty"`
	} `json:"exclude,omitempty"`
	Include []struct {
		Rule string `json:"rule,omitempty"`
	} `json:"include,omitempty"`
	Type string `json:"type,omitempty"`
}

// ScanPayloadError defines the info returned by burp when there is controlled
// error creating a scan.
type ScanPayloadError struct {
	Type string
	Err  string `json:"error"`
}

func (s ScanPayloadError) Error() string {
	return fmt.Sprintf("%s: %s", s.Type, s.Err)
}
