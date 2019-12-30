package cmd

import (
	"fmt"

	"github.com/amanelis/bespin/backend"
	h "github.com/amanelis/bespin/helpers"
	"github.com/spf13/cobra"
)

var (
	// DryRun does not commit or change data
	DryRun bool

	// B - main backend interface that holds all functionality
	B *backend.Backend

	rootCmd = &cobra.Command{
		Use:   "sigma",
		Short: fmt.Sprintf("%s: ECDSA/RSA key generation, signing, AES encrypt/decrypt, and secure backup", h.GFgB("Sigma CLI")),
		Run: func(cmd *cobra.Command, args []string) {
			B.Welcome()
		},
	}
)

// Execute executes the root command.
func Execute(b *backend.Backend) error {
	B = b

	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(preConfig)

	// root
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(dsaCmd)
	rootCmd.AddCommand(infoCmd)

	// flags
	rootCmd.PersistentFlags().BoolVarP(&DryRun, "dry-run", "d", false,
		"dry, no commits to real data")

	// dsa
	dsaCmd.PersistentFlags().StringVarP(&dsaType, "type", "t", "",
		"type of key: [ecdsa, eddsa, rsa.....]")
	dsaCmd.MarkFlagRequired("type")

	dsaCmd.AddCommand(dsaCreateCmd)
	dsaCmd.AddCommand(dsaGetCmd)
	dsaCmd.AddCommand(dsaListCmd)
	dsaCmd.AddCommand(dsaSignCmd)
	dsaCmd.AddCommand(dsaVerifyCmd)
	dsaCmd.AddCommand(dsaImportPubCmd)

	// Fire post configuration
	postConfig()
}

func preConfig() {
	if DryRun {
		fmt.Printf("%s", h.YFgB("*** --dry-run enabled, no data will be saved ***\n"))
	}
}

func postConfig() {
	// ...
}
