package cmd

import (
	"github.com/spf13/cobra"
	"github.com/amanelis/bespin/backend"
)

var (
	cfgFile     string
	userLicense string

	B *backend.Backend

	rootCmd = &cobra.Command{
		Use:   "sigma",
		Short: "SigmaInc, HSM key generation, signing and AES encrypt/decrypt",
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

	// keys
	keysCmd.AddCommand(keysCreateCmd)
	keysCmd.AddCommand(keysGetCmd)
	keysCmd.AddCommand(keysListCmd)
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
