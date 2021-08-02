package cmd

import (
	"fmt"

	h "github.com/block27/core/helpers"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use: "version",
	Run: func(cmd *cobra.Command, args []string) {
		version, err := h.ReadFile("./VERSION")
		if err != nil {
			panic(err)
		}
		fmt.Println("-------------------------------")
		fmt.Printf("Version: %s", h.WFgB(version))
		fmt.Println("-------------------------------")
	},
}
