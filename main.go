package main

import (
	"github.com/amanelis/bespin/config"
	h "github.com/amanelis/bespin/helpers"
	b "github.com/amanelis/bespin/services/bbolt"
	"github.com/amanelis/bespin/services/keys"
)

func NewClient() (*BackendConfiguration, error) {
	c, err := config.LoadConfig(config.ConfigDefaults)
	if err != nil {
		return nil, err
	}

	bDb, err := b.NewDB("/tmp/botldb")
	if err != nil {
		panic(err)
	}

	// Base BackendConfiguration to link structs and objects
	var bc = &BackendConfiguration{
		C: &c,
		D: bDb,
		L: config.LoadLogger(c),
	}

	// Call welcome notification message on start
	bc.Welcome()

	return bc, nil
}

func main() {
	// Initalize a new client, the base entrpy point to the application code
	c, _ := NewClient()

	// Defer the database connection
	defer c.D.Close()

	// Check and ensure correct USB/serial peripherals have correct authentication
	if err := c.ValidateKeys(); err != nil {
		panic(err)
	}

	// Begin key generation and storage into flat yaml file
	kN, er := keys.NewECDSA(*c.C, "some-name")
	if er != nil {
		panic(er)
	}

	// Try and get the new key that was created.
	kF, e := keys.GetECDSA(*c.C, kN.FilePointer())
	if e != nil {
		panic(e)
	}

	c.L.Infof("--------- NEW KEY -----------------------------")
	c.L.Infof("Key ID: %s", h.MagentaFgD(kF.FilePointer()))
	c.L.Infof("Key FP: %s", h.MagentaFgD(kF.Struct().Fingerprint))
	c.L.Infof("	privateKey: %s......", kF.Struct().PrivateKeyB64[0:64])
	c.L.Infof("	publicKey:  %s......", kF.Struct().PublicKeyB64[0:64])

	c.L.Infof("	privatePemPath: %s", kF.Struct().PrivatePemPath)
	c.L.Infof("	privateKeyPath: %s", kF.Struct().PrivateKeyPath)
	c.L.Infof("	publicKeyPath:  %s", kF.Struct().PublicKeyPath)
	c.L.Infof("--------- NEW KEY -----------------------------")

	objB64, _ := kF.Marshall()

	// Insert value to boltDB
	if err := c.D.InsertKey([]byte(kF.FilePointer()), []byte(objB64)); err != nil {
		panic(err)
	}

	// Get value from boltDB
	value, _ := c.D.GetVal([]byte(kF.FilePointer()))
	newKy, _ := keys.NewECDSABlank(*c.C)

	newKy, _ = newKy.Unmarshall(string(value))
	c.L.Infof("Boltdb keyB64['GID']: '%s'", h.GreenFgD(newKy.FilePointer()))

	keys, _ := c.D.AllKeys()
	for _, v := range keys {
		c.L.Infof("%s='%s'", h.MagentaFgD("Key"), h.GreenFgB(string(v)))
	}
}
