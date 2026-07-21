// Package main is a fixture that pins a small, deterministic set of Go module
// dependencies so package-checker has a realistic go.mod/go.sum to scan.
package main

import (
	_ "github.com/BurntSushi/toml"
	_ "golang.org/x/sys/cpu"
	_ "golang.org/x/text/language"
)

func main() {}
