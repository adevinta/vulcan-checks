package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

type score struct {
	Score *float32 `yaml:"score,omitempty"`
}

func loadRuleScoresFromDir(dir string) (map[string]float32, error) {
	ruleScores := make(map[string]float32)

	fi, err := os.Stat(dir)
	if err != nil {
		return ruleScores, err
	}

	if !fi.IsDir() {
		err := fmt.Errorf("%s is not a directory", dir)
		return ruleScores, err
	}

	fileList, err := filepath.Glob(dir + "/*")
	if err != nil {
		return ruleScores, err
	}

	for _, file := range fileList {
		if strings.HasSuffix(file, ".rule") {
			fileRuleScores, err := loadRuleScoresFromFile(file)
			if err != nil {
				return ruleScores, err
			}

			for k, v := range fileRuleScores {
				if v.Score != nil {
					ruleScores[k] = *v.Score
				}
			}
		}
	}

	return ruleScores, nil
}

func loadRuleScoresFromFile(file string) (map[string]score, error) {
	ruleScores := make(map[string]score)

	if file == "" {
		return ruleScores, nil
	}

	filename, _ := filepath.Abs(file)

	ruleBase := filepath.Base(filename)
	if filepath.Ext(ruleBase) == ".rule" {
		ruleBase = ruleBase[0 : len(ruleBase)-5]
	}

	yamlData, err := ioutil.ReadFile(filename)
	if err != nil {
		return ruleScores, err
	}

	err = yaml.Unmarshal(yamlData, &ruleScores)
	if err != nil {
		return ruleScores, err
	}

	return ruleScores, nil
}
