package cmd

import (
	"encoding/hex"
	"fmt"

	h "github.com/amanelis/bespin/helpers"
	k "github.com/amanelis/bespin/services/keys/ecdsa"

	"github.com/spf13/cobra"
)

var (
	// Create flags ...
	createName string
	createType string
	createSize int

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
	keysCreateCmd.Flags().IntVarP(&createSize, "size", "s", 256, "size")
	keysCreateCmd.MarkFlagRequired("name")
	keysCreateCmd.MarkFlagRequired("type")

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

		if len(keys) == 0 {
			B.L.Printf("No keys available")
		} else {
			k.PrintKeys(keys)
			// for _, f := range keys {
			// 	k.PrintKey(f.Struct(), B.L)
			// 	fmt.Println()
			// }
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

		sig, err := key.Sign(dataR)
		if err != nil {
			panic(err)
		}

		B.L.Printf("SHA(%s) = %x", signFilePath, sig.SHA[:])
		B.L.Printf("MD5(%s) = %x", signFilePath, hex.EncodeToString(sig.MD5[:]))
		B.L.Printf("Signature: \n\t\tr[%d]=0x%x \n\t\ts[%d]=0x%x",
			len(sig.R.Text(10)), sig.R, len(sig.S.Text(10)), sig.S)
		B.L.Printf("Verified: \n\t\t%t", key.Verify(dataR, sig))
	},
}
