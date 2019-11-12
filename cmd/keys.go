package cmd

import (
	// "encoding/hex"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/keys/ecdsa"
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

	// Verify flags
	verifyIdentifier    string
	verifyFilePath      string
	verifySignaturePath string
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

	// Verify flags ...
	keysVerifyCmd.Flags().StringVarP(&verifyIdentifier, "identifier", "i", "", "identifier required")
	keysVerifyCmd.Flags().StringVarP(&verifyFilePath, "file", "f", "", "file required")
	keysVerifyCmd.Flags().StringVarP(&verifySignaturePath, "signature", "s", "", "signature required")
	keysVerifyCmd.MarkFlagRequired("identifier")
	keysVerifyCmd.MarkFlagRequired("file")
	keysVerifyCmd.MarkFlagRequired("signature")
}

var keysCmd = &cobra.Command{
	Use: "keys",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf(fmt.Sprintf("%s", helpers.RedFgB("requires an argument")))
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {},
}

var keysCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new key pair",
	Run: func(cmd *cobra.Command, args []string) {
		key, e := ecdsa.NewECDSA(*B.C, createName, createSize)
		if e != nil {
			panic(e)
		}

		ecdsa.PrintKeyTW(key.Struct())
	},
}

var keysGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get key by identifier",
	Run: func(cmd *cobra.Command, args []string) {
		key, e := ecdsa.GetECDSA(*B.C, getIdentifier)
		if e != nil {
			panic(e)
		}

		ecdsa.PrintKeyTW(key.Struct())
	},
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys",
	Run: func(cmd *cobra.Command, args []string) {
		keys, err := ecdsa.ListECDSA(*B.C)
		if err != nil {
			panic(err)
		}

		if len(keys) == 0 {
			B.L.Printf("No keys available")
		} else {
			ecdsa.PrintKeysTW(keys)
		}
	},
}

var keysSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data with Key",
	Run: func(cmd *cobra.Command, args []string) {
		key, err := ecdsa.GetECDSA(*B.C, signIdentifier)
		if err != nil {
			panic(err)
		}

		// Read the file ready be signed / this should probably be hashed
		// if size > key bit size anyways.
		data, derr := helpers.ReadBinary(signFilePath)
		if derr != nil {
			panic(derr)
		}

		// Sign the data with the private key used internally
		sig, err := key.Sign(data)
		if err != nil {
			panic(err)
		}

		// Tell the sig receiver to asn1/der, this used for verification later
		derD, err := sig.SigToDER()
		if err != nil {
			panic(err)
		}

		// Now write a signarture.der file to hold the signature
		derF := fmt.Sprintf("/var/data/keys/%s/signature-%d.der", key.FilePointer(),
			int32(time.Now().Unix()))
		if _, err := helpers.WriteBinary(derF, derD); err != nil {
			panic(err)
		}

		// B.L.Printf("SHA(%s) = %x", signFilePath, sig.SHA[:])
		// B.L.Printf("MD5(%s) = %x", signFilePath, hex.EncodeToString(sig.MD5[:]))
		B.L.Printf("Signature: \n\t\tr[%d]=0x%x \n\t\ts[%d]=0x%x\n\t\tder=%s",
			len(sig.R.Text(10)), sig.R, len(sig.S.Text(10)), sig.S, derF)
		B.L.Printf("Verified: \n\t\t%t", key.Verify(data, sig))

	},
}

var keysVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify signed data",
	Run: func(cmd *cobra.Command, args []string) {
		key, err := ecdsa.GetECDSA(*B.C, verifyIdentifier)
		if err != nil {
			panic(err)
		}

		// Read the file ready be signed / this should probably be hashed
		// if size > key bit size anyways.
		data, derr := helpers.ReadBinary(verifyFilePath)
		if derr != nil {
			panic(derr)
		}

		// Read the signature file and convert to an ecdsaSigner
		sign, derr := ecdsa.LoadSignature(verifySignaturePath)
		if derr != nil {
			panic(derr)
		}

		B.L.Printf("Signature: \n\t\tr[%d]=0x%x \n\t\ts[%d]=0x%x\n\t\tder=%s",
			len(sign.R.Text(10)), sign.R, len(sign.S.Text(10)), sign.S, verifySignaturePath)
		B.L.Printf("Verified: \n\t\t%t", key.Verify(data, sign))
	},
}
