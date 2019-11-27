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
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(infoCmd)

	// flags
	rootCmd.PersistentFlags().BoolVarP(&DryRun, "dry-run", "d", false, "dry, no commits to real data")

	// keys
	keysCmd.AddCommand(keysCreateCmd)
	keysCmd.AddCommand(keysGetCmd)
	keysCmd.AddCommand(keysListCmd)
	keysCmd.AddCommand(keysSignCmd)
	keysCmd.AddCommand(keysVerifyCmd)
	keysCmd.AddCommand(keysImportPubCmd)

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
