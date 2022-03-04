/*
Copyright 2019 Adevinta
*/

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	exposedPath "github.com/adevinta/vulcan-checks/cmd/vulcan-exposed-http-endpoint/path"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("usage:vulcan-exposed-path-encoder source_file_to_encode")
		os.Exit(1)
	}
	f := path.Clean(os.Args[1])
	contents, err := ioutil.ReadFile(f)
	if err != nil {
		fmt.Printf("error reading file %s: %v", f, err)
		os.Exit(1)
	}
	lines := strings.Split(string(contents), "\n")
	paths := []exposedPath.Path{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		p := exposedPath.Path{Path: line}
		paths = append(paths, p)
	}
	output := f + ".json"
	err = writePaths(paths, f)
	if err != nil {
		fmt.Printf("error writing file %s: %v", output, err)
		os.Exit(1)
	}
}

// writePaths writes the paths to the specified json file.
func writePaths(p []exposedPath.Path, file string) error {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close() //nolint
	encoder := json.NewEncoder(f)
	return encoder.Encode(p)
}
