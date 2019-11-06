package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
  Use:   "version",
  Short: "Print the version number of Sigma",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("Sigma v0.9 -- HEAD")
  },
}
