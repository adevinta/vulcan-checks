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

// Path contains the conditions that have to be met consider the check positive
// for resource.
type Path struct {
	Path   string `json:"path"`
	Status *int   `json:"status,omitempty"`
	RegExp string `json:"reg_exp,omitempty"`
}

// Paths Represents a set of paths to check for.
type Paths []Path

// LoadFrom reads a list of paths from a file and populates the
// corresponding Path structure.
func (p Paths) LoadFrom(file string) ([]Path, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close() // nolint
	d := json.NewDecoder(f)
	paths := Paths{}
	err = d.Decode(&paths)
	if err != nil {
		return nil, err
	}
	p = append(p, paths...)
	return p, nil
}

// WriteTo writes the paths to the specified json file.
func (p *Paths) WriteTo(file string) error {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close() //nolint
	encoder := json.NewEncoder(f)
	return encoder.Encode(p)
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
		paths, err = paths.LoadFrom(currentPath)
		if err != nil {
			wd, _ := os.Getwd()
			err := fmt.Errorf("error opening file: %s, working directory %s", f.Name(), wd)
			return nil, err
		}
	}
	return paths, err
}
