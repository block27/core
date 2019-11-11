package cmd

import (
	"fmt"

	"github.com/amanelis/bespin/helpers"
	"github.com/spf13/cobra"
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
