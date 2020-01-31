package main

import (
	// "bytes"
	// "crypto/ecdsa"
	"crypto/x509"
	// "crypto/elliptic"
	// "encoding/gob"
	"fmt"
	// "math/big"

	"github.com/amanelis/bespin/helpers"
)

func main() {
	fmt.Println("Hello")

	priKpath := "/tmp/data/keys/de5d6591-645a-4366-a27e-bedc8d96ef6a/private.key"
	// pubKpath := "/var/data/keys/602102b3-b5ca-488e-8fc3-efa72c9ac83d/public.key"

	data, derr := helpers.ReadBinary(priKpath)
	if derr != nil {
		panic(derr)
	}

	privateKey, err := x509.ParseECPrivateKey(data)
	if err != nil {
		panic(err)
	}

	fmt.Println(privateKey.PublicKey.Curve)
	fmt.Println(privateKey.PublicKey.X)
	fmt.Println(privateKey.PublicKey.Y)
	fmt.Println(privateKey.D)

	fmt.Println(privateKey.Public())
}
