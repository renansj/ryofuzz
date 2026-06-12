package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	appVersion = "dev"
	appCommit  = "none"
	appDate    = "unknown"
)

func SetVersion(version, commit, date string) {
	appVersion = version
	appCommit = commit
	appDate = date
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ryofuzz %s (commit: %s, built: %s)\n", appVersion, appCommit, appDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
