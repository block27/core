package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	h "github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/dsa/ecdsa"
	"github.com/amanelis/bespin/services/dsa/eddsa"
	"github.com/amanelis/bespin/services/dsa/signature"
)

var (
	// Global flags ...
	dsaType string

	// Create flags ...
	createName  string
	createCurve string

	// List flags ...
	// ... none at the moment  ...

	// Get flags ...
	getIdentifier string

	// Sign flags
	signIdentifier string
	signFilePath   string

	// Verify flags
	verifyIdentifier    string
	verifyFilePath      string
	verifySignaturePath string

	// ImportPub flags
	importPubName  string
	importPubCurve string
	importPubFile  string
)

func init() {
	// Create flags ...
	dsaCreateCmd.Flags().StringVarP(&createName, "name", "n", "", "name required")
	dsaCreateCmd.Flags().StringVarP(&createCurve, "curve", "c", "prime256v1", "default: prime256v1")
	dsaCreateCmd.MarkFlagRequired("name")

	// Get flags ...
	dsaGetCmd.Flags().StringVarP(&getIdentifier, "identifier", "i", "", "identifier required")
	dsaGetCmd.MarkFlagRequired("identifier")

	// List flags ...
	// ...

	// Sign flags ...
	dsaSignCmd.Flags().StringVarP(&signIdentifier, "identifier", "i", "", "identifier required")
	dsaSignCmd.Flags().StringVarP(&signFilePath, "file", "f", "", "file required")
	dsaSignCmd.MarkFlagRequired("identifier")
	dsaSignCmd.MarkFlagRequired("file")

	// Verify flags ...
	dsaVerifyCmd.Flags().StringVarP(&verifyIdentifier, "identifier", "i", "", "identifier required")
	dsaVerifyCmd.Flags().StringVarP(&verifyFilePath, "file", "f", "", "file required")
	dsaVerifyCmd.Flags().StringVarP(&verifySignaturePath, "signature", "s", "", "signature required")
	dsaVerifyCmd.MarkFlagRequired("identifier")
	dsaVerifyCmd.MarkFlagRequired("file")
	dsaVerifyCmd.MarkFlagRequired("signature")

	// ImportPub flags  ...
	dsaImportPubCmd.Flags().StringVarP(&importPubName, "name", "n", "", "name required")
	dsaImportPubCmd.Flags().StringVarP(&importPubCurve, "curve", "c", "", "curve required")
	dsaImportPubCmd.Flags().StringVarP(&importPubFile, "publicKey", "p", "", "publicKey required")
}

func invalidKeyType() string {
	return fmt.Sprintf("Invalid keyType passed (%s), usage: [ecdsa, eddsa, rsa]\n", dsaType)
}

var dsaCmd = &cobra.Command{
	Use: "dsa",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf(fmt.Sprintf("%s", h.RFgB("requires an argument")))
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {},
}

var dsaCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new key pair",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CFgB("=== Keys[CREATE]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		switch dsaType {
		case "ecdsa":
			key, e := ecdsa.NewECDSA(*B.C, createName, createCurve)
			if e != nil {
				panic(e)
			}

			ecdsa.PrintKeyTW(key.Struct())
		case "eddsa":
			key, e := eddsa.NewEDDSA(*B.C, createName)
			if e != nil {
				panic(e)
			}

			eddsa.PrintKeyTW(key.Struct())
		default:
			B.L.Errorf(invalidKeyType())
		}
	},
}

var dsaGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get key by identifier",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CFgB("=== Keys[GET]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		switch dsaType {
		case "ecdsa":
			key, e := ecdsa.GetECDSA(*B.C, getIdentifier)
			if e != nil {
				panic(e)
			}

			ecdsa.PrintKeyTW(key.Struct())
		case "eddsa":
			key, e := eddsa.GetEDDSA(*B.C, getIdentifier)
			if e != nil {
				panic(e)
			}

			eddsa.PrintKeyTW(key.Struct())
		default:
			B.L.Errorf(invalidKeyType())
		}
	},
}

var dsaListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CFgB("=== Keys[LIST]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		switch dsaType {
		case "ecdsa":
			keys, err := ecdsa.ListECDSA(*B.C)
			if err != nil {
				panic(err)
			}

			if len(keys) == 0 {
				B.L.Printf("No keys available")
			} else {
				ecdsa.PrintKeysTW(keys)
			}
		case "eddsa":
			keys, err := eddsa.ListEDDSA(*B.C)
			if err != nil {
				panic(err)
			}

			if len(keys) == 0 {
				B.L.Printf("No keys available")
			} else {
				eddsa.PrintKeysTW(keys)
			}
		default:
			B.L.Errorf(invalidKeyType())
		}
	},
}

var dsaSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data with Key",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CFgB("=== Keys[SIGN]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		// var key interface{}
		//
		// switch dsaType {
		// case "ecdsa":
		// 	var err error
		//
		// 	key, err = ecdsa.GetECDSA(*B.C, signIdentifier)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		//
		// 	key = key.(ecdsa.KeyAPI)
		// case "eddsa":
		// 	var err error
		//
		// 	key, err = eddsa.GetEDDSA(*B.C, signIdentifier)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		//
		// 	key = key.(eddsa.KeyAPI)
		// default:
		// 	B.L.Errorf(invalidKeyType())
		// }

		key, err := ecdsa.GetECDSA(*B.C, signIdentifier)
		if err != nil {
			panic(err)
		}

		// Read the file ready be signed / this should probably be hashed
		// if size > key bit size anyways.
		file, derr := h.NewFile(signFilePath)
		if derr != nil {
			panic(derr)
		}

		// Sign the data with the private key used internally
		sig, serr := key.Sign([]byte(file.GetSHA()))
		if serr != nil {
			panic(serr)
		}

		// Tell the sig receiver to asn1/der, this used for verification later
		derD, err := sig.SigToDER()
		if err != nil {
			panic(err)
		}

		// Now write a signarture.der file to hold the signature
		derF := fmt.Sprintf("/var/data/keys/%s/%s/signature-%d.der", dsaType, key.FilePointer(),
			int32(time.Now().Unix()))
		if _, err := h.WriteBinary(derF, derD); err != nil {
			panic(err)
		}

		B.L.Printf("%s%s%s%s", h.WFgB("=== MD5("),
			h.RFgB(signFilePath), h.WFgB(") = "),
			h.GFgB(file.GetMD5()))

		B.L.Printf("%s%s%s%s", h.WFgB("=== SHA("),
			h.RFgB(signFilePath), h.WFgB(") = "),
			h.GFgB(file.GetSHA()))

		B.L.Printf("%s%s%s\n\t\tr[%d]=0x%x \n\t\ts[%d]=0x%x",
			h.WFgB("=== Signature("),
			h.RFgB(derF),
			h.WFgB(")"),
			len(sig.R.Text(10)), sig.R, len(sig.S.Text(10)), sig.S)

		// B.L.Printf("%s%s", h.WhiteFgB("=== Verified: "),
		// 	h.GreenFgB(key.Verify(file.GetBody(), sig)))
	},
}

var dsaVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify signed data",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CFgB("=== Keys[VERIFY]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		key, err := ecdsa.GetECDSA(*B.C, verifyIdentifier)
		if err != nil {
			panic(err)
		}

		// Read the file ready be signed / this should probably be hashed
		// if size > key bit size anyways.
		file, derr := h.NewFile(verifyFilePath)
		if derr != nil {
			panic(derr)
		}

		// Read the signature file and convert to an ecdsaSigner
		sig, derr := signature.LoadSignature(verifySignaturePath)
		if derr != nil {
			panic(derr)
		}

		B.L.Printf("%s%s", h.WFgB("=== Verified: "),
			h.GFgB(key.Verify([]byte(file.GetSHA()), sig)))
	},
}

var dsaImportPubCmd = &cobra.Command{
	Use:   "importPub",
	Short: "Import a public key",
	PreRun: func(cmd *cobra.Command, args []string) {
		B.L.Printf("%s", h.CFgB("=== Keys[IMPORT:PUB]"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		pub, err := h.NewFile(importPubFile)
		if err != nil {
			panic(err)
		}

		key, err := ecdsa.ImportPublicECDSA(*B.C, importPubName, importPubCurve, pub.GetBody())
		if err != nil {
			panic(err)
		}

		ecdsa.PrintKeyTW(key.Struct())
	},
}
