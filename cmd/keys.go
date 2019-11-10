package cmd

import (
	"crypto/sha256"
	"fmt"

	h "github.com/amanelis/bespin/helpers"
	k "github.com/amanelis/bespin/services/keys/ecdsa"

	"github.com/spf13/cobra"
)

var (
	// Create flags ...
	createName string
	createType string
	createSize uint16

	// List flags ...
	// ...

	// Get flags ...
	getIdentifier string

	// Sign flags
	signIdentifier string
	signFilePath   string
)

func init() {
	// Create flags ...
	keysCreateCmd.Flags().StringVarP(&createName, "name", "n", "", "name required")
	keysCreateCmd.Flags().StringVarP(&createType, "type", "t", "ecdsa", "type")
	keysCreateCmd.Flags().Uint16VarP(&createSize, "size", "s", 256, "size")
	keysCreateCmd.MarkFlagRequired("name")

	// Get flags ...
	keysGetCmd.Flags().StringVarP(&getIdentifier, "identifier", "i", "", "identifier required")
	keysGetCmd.MarkFlagRequired("identifier")

	// List flags ...
	// ...

	// Sign flags ...
	keysSignCmd.Flags().StringVarP(&signIdentifier, "identifier", "i", "", "identifier required")
	keysSignCmd.Flags().StringVarP(&signFilePath, "file", "f", "", "file required")
	keysSignCmd.MarkFlagRequired("identifier")
	keysSignCmd.MarkFlagRequired("file")
}

var keysCmd = &cobra.Command{
	Use: "keys",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf(fmt.Sprintf("%s", h.RedFgB("requires an argument")))
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {},
}

var keysCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create new key pairs",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CyanFgB("Keys[CREATE]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		key, e := k.NewECDSA(*B.C, createName, createSize)
		if e != nil {
			panic(e)
		}

		k.PrintKey(key.Struct(), B.L)
	},
}

var keysGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get key by identifier",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CyanFgB("Keys[GET]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		key, e := k.GetECDSA(*B.C, getIdentifier)
		if e != nil {
			panic(e)
		}

		k.PrintKey(key.Struct(), B.L)
	},
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CyanFgB("Keys[LIST]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		keys, err := k.ListECDSA(*B.C)
		if err != nil {
			panic(err)
		}

		for _, f := range keys {
			k.PrintKey(f.Struct(), B.L)
			fmt.Println()
		}
	},
}

var keysSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data with a public Key",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CyanFgB("Keys[SIGN]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		key, e := k.GetECDSA(*B.C, signIdentifier)
		if e != nil {
			panic(e)
		}

		dataR := h.ReadBinary(signFilePath)
		dataH := sha256.Sum256(dataR)

		fmt.Printf("SHA256(%s)= %x\n", signFilePath, dataH)

		sig, err := key.Sign(dataR)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Signature: \n\tr=0x%x \n\ts=0x%x\n", sig.R, sig.S)
		fmt.Printf("Verified: %t\n", key.Verify(dataR, sig))
	},
}
