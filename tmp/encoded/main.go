package main

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/amanelis/core-zero/helpers"
)

func main() {
	if len(os.Args) < 1 {
		panic("incorrect args passed, please pass private key path")
	}

	priKpath := os.Args[1]

	fmt.Println("----------------------------------------------------------------")
	fmt.Println(helpers.WFgB("private.der: "), priKpath)
	fmt.Println("----------------------------------------------------------------")

	data, derr := helpers.ReadBinary(priKpath)
	if derr != nil {
		panic(derr)
	}

	fmt.Printf("Raw PriKey: %0x\n", data)

	privateKey, err := x509.ParseECPrivateKey(data)
	if err != nil {
		panic(err)
	}

	fmt.Println(helpers.WFgB("Curve: "), helpers.GFgB(privateKey.PublicKey.Curve.Params().Name))
	fmt.Println(helpers.WFgB("PriKey.D: "), helpers.RFgB(privateKey.D))
	fmt.Println(helpers.WFgB("PriKey By: "), helpers.RFgB(privateKey.D.Bytes()))
	fmt.Println(helpers.WFgB("PriKey 0x: "), helpers.RFgB(fmt.Sprintf("%02x", privateKey.D)))
	fmt.Println(helpers.WFgB("PubKey.X: "), helpers.YFgB(privateKey.PublicKey.X))
	fmt.Println(helpers.WFgB("PubKey.Y: "), helpers.YFgB(privateKey.PublicKey.Y))
	fmt.Println(helpers.WFgB("PubKey P: "), helpers.CFgB(privateKey.Params().P))
	fmt.Println(helpers.WFgB("PubKey V: "), helpers.CFgB(privateKey.Public()))

}
