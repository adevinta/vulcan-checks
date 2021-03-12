/*
Copyright 2021 Adevinta
*/

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	changeLogPrefix = "Drupal "
	changeLogSuffix = ","
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %v <drupal_version>\n", os.Args[0])
		os.Exit(1)
	}

	http.HandleFunc("/CHANGELOG.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%v%v%v", changeLogPrefix, os.Args[1], changeLogSuffix)
	})

	log.Fatal(http.ListenAndServe(":80", nil))
}
