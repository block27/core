package cmd

import (
  "errors"
  "fmt"

	h "github.com/amanelis/bespin/helpers"
	k "github.com/amanelis/bespin/services/keys"

  "github.com/spf13/cobra"
)

var (
	name       string
  identifier string
)

func init() {
	keysCreateCmd.Flags().StringVarP(&name, "name", "n", "", "name required")
  keysGetCmd.Flags().StringVarP(&identifier, "identifier", "i", "", "identifier required")
}

var keysCmd = &cobra.Command{
  Use:   "keys",
  Args: func(cmd *cobra.Command, args []string) error {
    if len(args) < 1 {
      return errors.New(fmt.Sprintf("%s", h.RedFgB("requires an argument")))
    }

    return nil
  },
  Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keys")
  },
}

var keysCreateCmd = &cobra.Command{
  Use:   "create",
  Short: "Create new key pairs",
  PreRun: func(cmd *cobra.Command, args []string) {
    B.L.Printf("%s", h.CyanFgB("Keys[CREATE]"))
  },
  Run: func(cmd *cobra.Command, args []string) {
		key, e := k.NewECDSA(*B.C, name)
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
    key, e := k.GetECDSA(*B.C, identifier)
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
