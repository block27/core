package cmd

import "github.com/spf13/cobra"

var infoCmd = &cobra.Command{
	Use: "info",
	Run: func(cmd *cobra.Command, args []string) {
		B.Welcome()
	},
}
