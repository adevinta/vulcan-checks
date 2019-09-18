package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/adevinta/vulcan-report"
	version "github.com/knqyf263/go-rpm-version"
	"gopkg.in/resty.v1"

	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
)

var checkName = "vulcan-docker-image"

type options struct {
	PortauthorityURL string `json:"portauthority_url"`
}

type CreateScanRequest struct {
	Image Image `json:"Image"`
}

type Image struct {
	ID       int    `json:"ID"`
	Registry string `json:"Registry"`
	Repo     string `json:"Repo"`
	Tag      string `json:"Tag"`
}

type GetScanResponse struct {
	Image struct {
		ID        int       `json:"ID"`
		Registry  string    `json:"Registry"`
		Repo      string    `json:"Repo"`
		Tag       string    `json:"Tag"`
		Digest    string    `json:"Digest"`
		FirstSeen time.Time `json:"FirstSeen"`
		LastSeen  time.Time `json:"LastSeen"`
		Features  []struct {
			Name            string `json:"Name"`
			NamespaceName   string `json:"NamespaceName"`
			VersionFormat   string `json:"VersionFormat"`
			Version         string `json:"Version"`
			AddedBy         string `json:"AddedBy"`
			Vulnerabilities []struct {
				Name          string `json:"Name"`
				NamespaceName string `json:"NamespaceName"`
				Description   string `json:"Description"`
				Link          string `json:"Link"`
				Severity      string `json:"Severity"`
				FixedBy       string `json:"FixedBy"`
			} `json:"Vulnerabilities,omitempty"`
		} `json:"Features"`
		Violations []struct {
			Type           string `json:"Type"`
			FeatureName    string `json:"FeatureName"`
			FeatureVersion string `json:"FeatureVersion"`
			Vulnerability  struct {
				Name          string `json:"Name"`
				NamespaceName string `json:"NamespaceName"`
				Description   string `json:"Description"`
				Link          string `json:"Link"`
				Severity      string `json:"Severity"`
				FixedBy       string `json:"FixedBy"`
			} `json:"Vulnerability"`
		} `json:"Violations"`
		Metadata struct {
			Data string `json:"data"`
		} `json:"Metadata"`
	} `json:"Image"`
}

type outdatedPackage struct {
	name     string
	version  string
	severity string
	fixedBy  string
}

type vulnerability struct {
	name     string
	severity string
	link     string
}

var vuln = report.Vulnerability{
	Summary:     "Outdated Packages in Docker Image (BETA)",
	Description: "Vulnerabilities have been found in outdated packages installed in the Docker image.",
	CWEID:       937,
	Recommendations: []string{
		"Update affected packages to the versions specified in the resources table or newer.",
		"This check is in BETA phase.",
	},
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target string, optJSON string, state state.State) error {
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}
	log.Printf("using %s as portauthority URL", opt.PortauthorityURL)

	slashSplit := strings.SplitAfterN(target, "/", 2)
	if len(slashSplit) <= 1 {
		return errors.New(target + " is not a valid target")
	}
	targetSplit := strings.Split(slashSplit[1], ":")
	if len(targetSplit) != 2 {
		return errors.New(target + "is not a valid target")
	}

	registryURL := "https://" + strings.Trim(slashSplit[0], "/")

	createScanRequest := CreateScanRequest{
		Image{
			Registry: registryURL,
			Repo:     targetSplit[0],
			Tag:      targetSplit[1],
		},
	}

	client := resty.New()

	request := client.R()
	request.SetHeader("Accept", "application/json")
	request.SetResult(CreateScanRequest{})
	request.SetBody(createScanRequest)
	request.SetContext(ctx)
	createScanResponse, err := request.Post(opt.PortauthorityURL)
	if err != nil {
		return err
	}
	createScanData, ok := createScanResponse.Result().(*CreateScanRequest)
	if !ok {
		return errors.New("response does not match CreateScanRequest type")
	}

	request = client.R()
	request.SetHeader("Accept", "application/json")
	request.SetResult(GetScanResponse{})
	request.SetContext(ctx)
	getScanResponse, err := request.Get(fmt.Sprintf("%s/%d?vulnerabilities&policy=default", opt.PortauthorityURL, createScanData.Image.ID))
	if err != nil {
		return err
	}
	results, ok := getScanResponse.Result().(*GetScanResponse)
	if !ok {
		return errors.New("response does not match GetScanResponse type")
	}

	ap := report.ResourcesGroup{
		Name: "Affected Packages",
		Header: []string{
			"Name",
			"Version",
			"Severity",
			"FixedBy",
		},
	}

	vp := report.ResourcesGroup{
		Name: "Package Vulnerabilities",
		Header: []string{
			"Name",
			"Version",
			"Vulnerabilities",
		},
	}

	var rows []map[string]string
	for _, feature := range results.Image.Features {
		if len(feature.Vulnerabilities) < 1 {
			continue
		}

		p := outdatedPackage{
			name:     feature.Name,
			version:  feature.Version,
			severity: "",
			fixedBy:  "0:0.0.0",
		}

		var vulns []vulnerability
		for _, vv := range feature.Vulnerabilities {
			score := getScore(vv.Severity)
			currentScore := getScore(p.severity)
			if score > currentScore {
				p.severity = vv.Severity
			}

			if isBiggerVersion(vv.FixedBy, p.fixedBy) {
				p.fixedBy = vv.FixedBy
			}
			v := vulnerability{
				name:     vv.Name,
				link:     vv.Link,
				severity: vv.Severity,
			}
			vulns = append(vulns, v)
		}

		score := getScore(p.severity)
		if score > vuln.Score {
			vuln.Score = score
		}

		// Sort vulns by severity and alphabetical order name.
		sort.Slice(vulns, func(i, j int) bool {
			v := vulns
			si := getScore(v[i].severity)
			sj := getScore(v[j].severity)
			switch {
			case si != sj:
				return si > sj
			default:
				return v[i].name < v[j].name
			}
		})

		var vulnsText []string
		for _, v := range vulns {
			t := fmt.Sprintf("[%s](%s) (%s)", v.name, v.link, v.severity)
			vulnsText = append(vulnsText, t)
		}

		affectedPackage := map[string]string{
			"Name":            p.name,
			"Version":         p.version,
			"Severity":        p.severity,
			"FixedBy":         p.fixedBy,
			"Vulnerabilities": strings.Join(vulnsText, "\n\n"),
		}

		rows = append(rows, affectedPackage)
	}

	// Sort rows by severity, alphabetical order of the package name and version.
	sort.Slice(rows, func(i, j int) bool {
		si := getScore(rows[i]["Severity"])
		sj := getScore(rows[j]["Severity"])
		switch {
		case si != sj:
			return si > sj
		case rows[i]["Name"] != rows[j]["Name"]:
			return rows[i]["Name"] < rows[j]["Name"]
		default:
			return rows[i]["Version"] < rows[j]["Version"]
		}
	})

	ap.Rows = rows
	vp.Rows = rows

	vuln.Resources = append(vuln.Resources, ap, vp)
	state.AddVulnerabilities(vuln)

	b, err := json.Marshal(results)
	if err != nil {
		log.Printf("error mashaling results: %v, %v", err, results)
	} else {
		state.Data = b
	}

	return nil
}

func getScore(severity string) float32 {
	if severity == "Critical" {
		return report.SeverityThresholdCritical
	}
	if severity == "High" {
		return report.SeverityThresholdHigh
	}
	if severity == "Medium" {
		return report.SeverityThresholdMedium
	}
	if severity == "Low" || severity == "Negligible" {
		return report.SeverityThresholdLow
	}
	return report.SeverityThresholdNone
}

func isBiggerVersion(n, c string) bool {
	// It is possible that is an RPM package and we found that hashicorp go-version
	// library is not working fine for those cases. For example we need to take
	// into account specials cases like the one mentioned here:
	// https://serverfault.com/questions/750761/what-does-the-1-before-the-package-name-mean-in-yum-log
	// or characters not allowed go-version (e.g. 2.2.15-60.el6_9.6).
	//
	// We will use go-rpm-version.
	vc := version.NewVersion(c)
	vn := version.NewVersion(n)

	return vc.LessThan(vn)
}
