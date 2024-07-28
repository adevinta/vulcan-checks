// Copyright 2024 Adevinta

// Vulcan-govulncheck uses govulncheck to report known vulnerabilities
// that affect Go code.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/jroimartin/sarif"
	"github.com/sirupsen/logrus"
)

const (
	// checkName is the name of the checktype.
	checkName = "vulcan-govulncheck"

	// defaultCWE is the CWE ID used by vulcan-govulncheck to
	// report the detected vulnerabilities. Govulncheck reports
	// vulnerable dependencies being used by the scanned
	// module. Thus, a single CWE ID is enough to characterize the
	// findings.
	defaultCWE = 937 // Using Components with Known Vulnerabilities
)

// logger is the logger used to log events from this specific
// checktype.
var logger = check.NewCheckLog(checkName)

// options contains the runtime options provided to the check.
type options struct {
	Depth  int    `json:"depth"`
	Branch string `json:"branch"`

	// Recursive specifies whether to recursively search
	// subdirectories for Go modules.
	Recursive bool `json:"recursive"`

	// Dir specifies the root of the file tree to anlyze relative
	// to the root of the repository.
	Dir string `json:"dir"`

	// Govulncheck args.

	DB   string `json:"db"`   // -db flag
	Tags string `json:"tags"` // -tags flag
	Test bool   `json:"test"` // -test flag
}

// main is the entrypoint of the checktype.
func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

// run contains the actual logic of the checktype.
func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	if target == "" {
		return errors.New("check target missing")
	}

	logger = logger.WithFields(logrus.Fields{
		"target":     target,
		"asset_type": assetType,
	})

	opt, err := parseOptions(optJSON)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	logger.WithFields(logrus.Fields{"options": opt}).Debug("using options")

	repoPath, _, err := helpers.CloneGitRepository(target, opt.Branch, opt.Depth)
	if err != nil {
		return fmt.Errorf("clone git repository: %w", err)
	}

	root := filepath.Join(repoPath, opt.Dir)

	var dirs []string
	if opt.Recursive {
		dirs, err = findGoModules(root)
		if err != nil {
			return fmt.Errorf("find go modules: %w", err)
		}
	} else {
		dirs = []string{root}
	}

	for _, dir := range dirs {
		vulns, err := runGovulncheck(ctx, repoPath, dir, opt)
		if err != nil {
			return fmt.Errorf("run govulncheck at %v: %w", dir, err)
		}
		state.AddVulnerabilities(vulns...)
	}

	return nil
}

// parseOptions decodes the JSON document containing the runtime
// options received by the check. If an option is not specified, it
// sets the default.
func parseOptions(optJSON string) (options, error) {
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return options{}, fmt.Errorf("JSON unmarshal: %w", err)
		}
	}

	if opt.Depth == 0 {
		opt.Depth = 1
	}

	return opt, nil
}

// runGovulncheck runs the govulncheck command and returns the list of
// detected vulnerabilities.
func runGovulncheck(ctx context.Context, repoPath, dir string, opt options) ([]report.Vulnerability, error) {
	var args []string
	if opt.DB != "" {
		args = append(args, "-db", opt.DB)
	}
	if opt.Tags != "" {
		args = append(args, "-tags", opt.Tags)
	}
	if opt.Test {
		args = append(args, "-test")
	}
	args = append(args, "-format", "sarif", "./...")

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "govulncheck", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run command: %w: %q", err, stderr.String())
	}

	rel, err := filepath.Rel(repoPath, dir)
	if err != nil {
		return nil, fmt.Errorf("relative path: %w", err)
	}

	vulns, err := parseSarif(&stdout, rel)
	if err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}

	return vulns, nil
}

// parseSarif parses the SARIF document read from the provided
// [io.Reader] and maps the results to the vulnerability data model
// expected by Vulcan (i.e. [report.Vulnerability]).
func parseSarif(r io.Reader, dir string) ([]report.Vulnerability, error) {
	l, err := sarif.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("decode SARIF document: %w", err)
	}

	var vulns []report.Vulnerability
	for _, run := range l.Runs {
		for _, result := range run.Results {
			vuln, err := toVuln(l, result, dir)
			if err != nil {
				return nil, fmt.Errorf("parse result: %w", err)
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

// toVuln converts a [sarif.Result] value belonging to the specified
// [sarif.Log] into a [report.Vulnerability] value.
func toVuln(l sarif.Log, result sarif.Result, dir string) (report.Vulnerability, error) {
	rule, found := l.FindRule(result.RuleID)
	if !found {
		return report.Vulnerability{}, fmt.Errorf("unknown rule: %v", result.RuleID)
	}

	var rscs []report.ResourcesGroup
	for _, cf := range result.CodeFlows {
		rsc := report.ResourcesGroup{
			Name:   cf.Message.Text,
			Header: []string{"module", "location", "function"},
		}
		for _, tf := range cf.ThreadFlows {
			for _, loc := range tf.Locations {
				row := make(map[string]string)
				row["module"] = loc.Module
				row["location"] = loc.Location.PhysicalLocation.String()
				row["function"] = loc.Location.Message.Text
				rsc.Rows = append(rsc.Rows, row)
			}
		}
		rscs = append(rscs, rsc)
	}

	locations := getLocations(result, dir)

	var resourceString string
	if mod := getVulnMod(result); mod != "" {
		resourceString = fmt.Sprintf("Module %v at %v", mod, locations)
	}
	vuln := report.Vulnerability{
		Summary:                rule.ShortDescription.Text,
		Score:                  calcScore(result),
		AffectedResource:       locations,
		AffectedResourceString: resourceString,
		Fingerprint:            helpers.ComputeFingerprint(result.RuleID, locations),
		CWEID:                  defaultCWE,
		Description:            rule.FullDescription.Text,
		Details:                result.Message.Text,
		Labels:                 []string{"issue"},
		Recommendations: []string{
			"Visit the linked references for more details.",
		},
		References: []string{rule.HelpURI},
		Resources:  rscs,
	}

	return vuln, nil
}

// getVulnMod returns the vulnerable Go module that originates the
// specified SARIF result. It returns an empty string if it not
// possible to parse the reported code flows.
func getVulnMod(result sarif.Result) string {
	if len(result.CodeFlows) == 0 {
		return ""
	}
	cf := result.CodeFlows[0]

	if len(cf.ThreadFlows) == 0 {
		return ""
	}
	tf := cf.ThreadFlows[0]

	if len(tf.Locations) == 0 {
		return ""
	}
	loc := tf.Locations[len(tf.Locations)-1]

	return loc.Module
}

// getLocations returns an ordered list of the locations where the
// issues were found.
func getLocations(result sarif.Result, dir string) string {
	var locs []string
	for _, loc := range result.Locations {
		l := strings.Replace(loc.PhysicalLocation.String(), "%SRCROOT%", dir, 1)
		locs = append(locs, l)
	}
	slices.Sort(locs)
	return strings.Join(locs, ",")
}

// calcScore calculates the numeric severity score of the
// vulnerability based on the level field of the provided SARIF
// result.
func calcScore(result sarif.Result) float32 {
	if result.Level == "error" {
		return report.SeverityThresholdHigh
	} else {
		return report.SeverityThresholdNone
	}
}

// findGoModules walks the file tree rooted at root looking for
// go.mod files. It returns the paths of the directories where a
// go.mod file was found.
func findGoModules(root string) ([]string, error) {
	var mods []string
	err := filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Base(path) == "go.mod" {
			mods = append(mods, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	return mods, nil
}
