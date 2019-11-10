package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
  "github.com/amanelis/bespin/helpers"
)

var versionCmd = &cobra.Command{
  Use: "version",
  Run: func(cmd *cobra.Command, args []string) {
    version, err := helpers.ReadFile("./VERSION")
    if err != nil {
      panic(err)
    }
    fmt.Println("-------------------------------")
    fmt.Printf("Version: %s", helpers.WhiteFgB(version))
    fmt.Println("-------------------------------")
  },
}
