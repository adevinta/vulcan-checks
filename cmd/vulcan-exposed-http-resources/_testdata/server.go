/*
Copyright 2020 Adevinta
*/

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

type FileSystem struct {
	fs http.FileSystem
}

func (fs FileSystem) Open(path string) (http.File, error) {
	f, err := fs.fs.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if s.IsDir() {
		index := strings.TrimSuffix(path, "/") + "/index.html"
		if _, err := fs.fs.Open(index); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: server DIRECTORY")
		os.Exit(1)
	}

	fs := http.FileServer(FileSystem{http.Dir(os.Args[1])})
	http.Handle("/", fs)

	log.Println("Listening on :3000...")
	err := http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatal(err)
	}
}
