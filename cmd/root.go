package cmd

import (
	"fmt"

	"github.com/amanelis/bespin/backend"
	"github.com/amanelis/bespin/helpers"
	"github.com/spf13/cobra"
)

var (
	cfgFile     string
	userLicense string

	// B - main backend interface that holds all functionality
	B *backend.Backend

	rootCmd = &cobra.Command{
		Use:   "sigma",
		Short: fmt.Sprintf("%s: ECDSA/RSA key generation, signing, AES encrypt/decrypt, and secure backup", helpers.GreenFgB("Sigma CLI")),
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
	cobra.OnInitialize(initConfig)

	// root
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(infoCmd)

	// keys
	keysCmd.AddCommand(keysCreateCmd)
	keysCmd.AddCommand(keysGetCmd)
	keysCmd.AddCommand(keysListCmd)
	keysCmd.AddCommand(keysSignCmd)
	keysCmd.AddCommand(keysVerifyCmd)
	keysCmd.AddCommand(keysImportPubCmd)
}

func initConfig() {
	// if cfgFile != "" {
	// 	// Use config file from the flag.
	// 	viper.SetConfigFile(cfgFile)
	// } else {
	// 	// Find home directory.
	// 	home, err := homedir.Dir()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	//
	// 	// Search config in home directory with name ".cobra" (without extension).
	// 	viper.AddConfigPath(home)
	// 	viper.SetConfigName(".cobra")
	// }
	//
	// viper.AutomaticEnv()
	//
	// if err := viper.ReadInConfig(); err == nil {
	// 	fmt.Println("Using config file:", viper.ConfigFileUsed())
	// }
}
