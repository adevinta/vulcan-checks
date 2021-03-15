/*
Copyright 2019 Adevinta
*/

package main

import (
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
	paths := exposedPath.Paths{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		p := exposedPath.Path{Path: line}
		paths = append(paths, p)
	}
	output := f + ".json"
	err = paths.WriteTo(output)
	if err != nil {
		fmt.Printf("error writing file %s: %v", output, err)
		os.Exit(1)
	}
}
