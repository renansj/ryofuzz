package main

import (
	"fmt"
	"os"

	"github.com/renansj/ryofuzz/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	cmd.SetVersion(version, commit, date)
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}
