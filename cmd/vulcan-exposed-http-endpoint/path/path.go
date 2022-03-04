/*
Copyright 2019 Adevinta
*/

package path

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Path defines the conditions for the check to find a vulnerability in a
// concrete path of an URL.
type Path struct {
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
	RegExp string `json:"reg_exp,omitempty"`
}

// UnmarshalJSON unmarshals a path from a JSON payload setting the Status field
// to -1 if not specified.
func (p *Path) UnmarshalJSON(data []byte) error {
	type path Path
	aux := path{Status: -1}
	err := json.Unmarshal(data, &aux)
	if err != nil {
		return err
	}
	*p = Path(aux)
	return nil
}

// Paths Represents a set of paths to check for.
type Paths map[Path]struct{}

// LoadFrom reads a list of paths from a file and populates the
// corresponding Path structure.
func (p Paths) LoadFrom(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close() // nolint
	d := json.NewDecoder(f)
	paths := []Path{}
	err = d.Decode(&paths)
	if err != nil {
		return err
	}
	p.Add(paths...)
	return nil
}

// Add adds some paths to the current set of paths.
func (p Paths) Add(paths ...Path) error {
	for _, lpath := range paths {
		p[lpath] = struct{}{}
	}
	return nil
}

// ReadDefault reads all the paths specified in the default folder.
func ReadDefault() (Paths, error) {
	files, err := ioutil.ReadDir("_paths/")
	if err != nil {
		return nil, err
	}
	paths := Paths{}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" {
			continue
		}
		currentPath := "_paths/" + f.Name()
		err = paths.LoadFrom(currentPath)
		if err != nil {
			wd, _ := os.Getwd()
			err := fmt.Errorf("error opening file: %s, working directory %s", f.Name(), wd)
			return nil, err
		}
	}
	return paths, err
}
