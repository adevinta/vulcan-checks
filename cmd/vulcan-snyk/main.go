package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"
	http "gopkg.in/src-d/go-git.v4/plumbing/transport/http"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
)

var (
	checkName = "vulcan-snyk"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		logger.WithFields(logrus.Fields{
			"repository": target,
		}).Debug("testing repository")

		if target == "" {
			return errors.New("check target missing")
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			return err
		}

		var auth *http.BasicAuth
		if targetURL.Host == "github.mpi-internal.com" {
			auth = &http.BasicAuth{
				Username: "username", // Can be anything except blank.
				Password: os.Getenv("GITHUB_ENTERPRISE_TOKEN"),
			}
		}

		repoPath := filepath.Join("/tmp", filepath.Base(targetURL.Path))
		err = os.RemoveAll(repoPath)
		if err != nil {
			return err
		}

		if err := os.Mkdir(repoPath, 0755); err != nil {
			return err
		}

		_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
			URL:  target,
			Auth: auth,
		})
		if err != nil {
			return err
		}

		if os.ExpandEnv("$SNYK_TOKEN") == "" {
			return fmt.Errorf("SNYK_TOKEN is not set")
		}

		output, code, err := command.Execute(ctx, logger, "snyk", append([]string{"auth", os.ExpandEnv("$SNYK_TOKEN")})...)
		if code != 0 {
			return fmt.Errorf("%s", output)
		}

		logger.Infof("auth: %s", output)
		if err != nil {
			return err
		}

		//output, _, _ := command.Execute(ctx, logger, "snyk", append([]string{"test", repoPath, "--all-sub-projects", "--json"})...)
		output, _, _ = command.Execute(ctx, logger, "snyk", append([]string{"test", repoPath, "--all-sub-projects"})...)
		logger.Infof("ls: %s", output)

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
