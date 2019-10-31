package main

import (
	"fmt"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/bbolt"
	"github.com/amanelis/bespin/services/keys"
	"github.com/amanelis/bespin/services/serial"
)

type BackendConfiguration struct {
	C	*config.ConfigReader
	D	bbolt.Datastore
	L	*logrus.Logger
}

func NewClient() (*BackendConfiguration, error) {
	c, err := config.LoadConfig(config.ConfigDefaults)
	if err != nil {
		return nil, err
	}

	bDb, err := bbolt.NewDB("/tmp/botldb")
	if err != nil {
		panic(err)
	}

	// Base BackendConfiguration to link structs and objects
	var bc = &BackendConfiguration{
		C: 		&c,
		D:  	bDb,
		L: 		config.LoadLogger(c),
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
	kN, er := keys.NewECDSA(*c.C)
	if er != nil {
		panic(er)
	}

	// Try and get the new key that was created.
	kF, e := keys.GetECDSA(*c.C, kN.Struct().GID.String())
	if e != nil {
		panic(e)
	}

	c.L.Infof("Key ID: %s", helpers.MagentaFgD(kF.Struct().GID.String()))
	c.L.Infof("Key FP: %s", helpers.MagentaFgD(kF.Struct().Fingerprint))
	c.L.Infof("	privateKey: %s......", kF.Struct().PrivateKeyB64[0:64])
	c.L.Infof("	publicKey:  %s......", kF.Struct().PublicKeyB64[0:64])

	c.L.Infof("	privatePemPath: %s", kF.Struct().PrivatePemPath)
	c.L.Infof("	privateKeyPath: %s", kF.Struct().PrivateKeyPath)
	c.L.Infof("	publicKeyPath:  %s", kF.Struct().PublicKeyPath)


	objB64, _ := kF.Marshall()

	c.D.InsertKey([]byte(kF.Struct().GID.String()), []byte(objB64))
	v, e := c.D.GetKey([]byte(kF.Struct().GID.String()))
	if e != nil {
		panic(e)
	}

	keyB64, _ := kF.Unmarshall(string(v))
	c.L.Infof("Boltdb keyB64['GID']: '%s'", helpers.GreenFgD(keyB64.Struct().GID.String()))

	// c.L.Infof("Boltdb key['name']: '%s'", helpers.GreenFgD(string(v)))
}

// RequestHardwareKeys ...
//
// This function calls the arduino board for the hardware keys via USB and
// there are a few details to be noted:
//
// key can be returned in raw or in base64
//
// The format of the key  is {type}.Request.{byte|base}.{length to read}
//
// KEY:
// key(base64) -> k.Request.base44 	// 44 bytes
// key(raw) -> k.Request.byte32 		// 32 bytes
//
// IV:
// iv(base64) -> i.Request.base24 	// 24 bytes
// iv(raw) -> i.Request.byte16 			// 16 bytes
func (b *BackendConfiguration) RequestHardwareKeys() (*crypto.AESCredentials, error) {
	c := serial.NewSerial("/dev/tty.usbmodem20021401", 115200)

	// Request KEY
	ky, ke := c.Request(serial.Request{
		Method: "k.Request.byte32\r",
		Size:   32,
	})

	if ke != nil {
		panic(ke)
	}

	// Request IV
	iv, ie := c.Request(serial.Request{
		Method: "i.Request.byte16\r",
		Size:   16,
	})

	if ie != nil {
		return nil, ie
	}

	b.L.Infof("ky(%d) verified, %s", len(string(ky)), helpers.GreenFgD("OK"))
	b.L.Infof("iv(%d) verified, %s", len(string(iv)), helpers.GreenFgD("OK"))

	aes, err := crypto.NewAESCredentials(ky, iv)
	if err != nil {
		return nil, err
	}

	return aes, nil
}

// ValidateKeys ...
//
// A Key/Iv will be stored on the hardware device itself. These two values
// are used to encrypt the two pins stored in the ext volumes [BASE1, BASE2]
//
// These values decrypted must match the two  pins stored on the hardware to
// work, if removed or altered, HSM  code will  not run. But key recovery is
// still possible.
func (b *BackendConfiguration) ValidateKeys() error {
	var extB1, extB2 string

	if runtime.GOOS == "darwin" {
		extB1 = fmt.Sprintf("%s/%s", "/Volumes/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/Volumes/BASE2", config.ExtBase2Path)
	} else if runtime.GOOS == "linux" {
		extB1 = fmt.Sprintf("%s/%s", "/media/pi/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/media/pi/BASE2", config.ExtBase2Path)
	} else {
		return fmt.Errorf("Unsupported OS")
	}

	paths := []string{
		config.HostMasterKeyPath,
		config.HostMasterIvPath,
		config.HostPin1,
		config.HostPin2,
		config.HostSerialPath,
		extB1,
		extB2,
	}

	// Check all paths, ensure every one exists
	for _, v := range paths {
		if !helpers.FileExists(v) {
			return fmt.Errorf("Missing [%s]", v)
		}
	}

	// Pull the Key/Iv off the hardware device
	aes, err := b.RequestHardwareKeys()
	if err != nil {
		return err
	}

	hmK, _ := helpers.ReadFile(config.HostMasterKeyPath)
	hmI, _ := helpers.ReadFile(config.HostMasterIvPath)

	if string(aes.Key()) != hmK {
		return fmt.Errorf("Key does not match Hardware(key)")
	}

	if string(aes.Iv()) != hmI {
		return fmt.Errorf("Iv does not match Hardware(iv)")
	}

	// Create a cypter service object - encryption/decryption
	c, _ := crypto.NewCrypter(
		[]byte(hmK),
		[]byte(hmI),
	)

	// Read ext1
	b1F, _ := helpers.ReadFile(extB1)
	hp1F, _ := helpers.ReadFile(config.HostPin1)

	dec1, _ := c.Decrypt([]byte(b1F))
	if string(dec1) != hp1F {
		return fmt.Errorf("Pin1 does not match, invalid ext authentication!")
	}

	// Read ext2
	b2F, _ := helpers.ReadFile(extB2)
	hp2F, _ := helpers.ReadFile(config.HostPin2)

	dec2, _ := c.Decrypt([]byte(b2F))
	if string(dec2) != hp2F {
		return fmt.Errorf("Pin2 does not match, invalid ext authentication!")
	}

	return nil
}

func (b *BackendConfiguration) Welcome() {
	fmt.Printf("%s\n", helpers.CyanFgB("----------------------------------------------------------------"))
	fmt.Printf("%s: %d\n", helpers.GreenFgB("- CPUs"), runtime.NumCPU())
	fmt.Printf("%s: %s\n", helpers.GreenFgB("- Arch"), runtime.GOARCH)
	fmt.Printf("%s: %s\n", helpers.GreenFgB("- Compiler"), runtime.Compiler)
	fmt.Printf("%s: %s\n", helpers.GreenFgB("- Runtime"), runtime.GOOS)
	fmt.Printf("%s\n", helpers.CyanFgB("----------------------------------------------------------------"))
}
