package main

import (
	"encoding/base64"
	"fmt"
	"runtime"

	"github.com/Sirupsen/logrus"
	// "github.com/tarm/serial"
	// github.com/jacobsa/go-serial/serial

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/keys"
	"github.com/amanelis/bespin/services/serial"
)

type BackendConfiguration struct {
	Config config.ConfigReader
	Logger *logrus.Logger
}

func NewClient() (*BackendConfiguration, error) {
	c, err := config.LoadConfig(config.ConfigDefaults)
	if err != nil {
		return nil, err
	}

	var bc = &BackendConfiguration{
		Config: c,
		Logger: config.LoadLogger(c),
	}

	// Call welcome notification message on start
	bc.Welcome()

	return bc, nil
}

func main() {
	// Initalize a new client, the base entrpy point to the application code
	c, _ := NewClient()

	// Check and ensure correct USB/serial peripherals have correct authentication
	c.ValidateKeys()

	k, er := keys.NewKey()
	if er !=nil {
		panic(er)
	}
	keys.SaveKey(c.Config, "r1", *k.Struct())

	r, _ := keys.FindKey(c.Config, "r1")
	fmt.Println("---------------------------------------------")
	fmt.Printf("R1: %s\n", r.PrivateKeyB64)
	fmt.Println("---------------------------------------------")

	sDec, _ := base64.StdEncoding.DecodeString(r.PrivateKeyB64)
  fmt.Println(string(sDec))

}

// USBFPGAHardwareKeys ...
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
		Size: 32,
	})

	if ke !=nil {
		panic(ke)
	}

	// Request IV
	iv, ie := c.Request(serial.Request{
		Method: "i.Request.byte16\r",
		Size: 16,
	})

	if ie !=nil {
		return nil, ie
	}

	fmt.Printf("ky(%d) verified, OK\n", len(string(ky)))
	fmt.Printf("iv(%d) verified, OK\n", len(string(iv)))

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
func (b *BackendConfiguration) ValidateKeys() {
	var extB1, extB2 string

	if runtime.GOOS == "darwin" {
		extB1 = fmt.Sprintf("%s/%s", "/Volumes/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/Volumes/BASE2", config.ExtBase2Path)
	} else if runtime.GOOS == "linux" {
		extB1 = fmt.Sprintf("%s/%s", "/media/pi/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/media/pi/BASE2", config.ExtBase2Path)
	} else {
		panic("Unsupported OS")
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
	for _, v :=  range paths {
		if !helpers.FileExists(v) {
			panic(fmt.Errorf("Missing [%s]", v))
		}
	}

	// Pull the Key/Iv off the hardware device
	aes, err := b.RequestHardwareKeys()
	if err !=nil {
		panic(err)
	}

	hmK, _ := helpers.ReadFile(config.HostMasterKeyPath)
	hmI, _ := helpers.ReadFile(config.HostMasterIvPath)

	if string(aes.Key()) != hmK {
		panic("Key does not match Hardware(key)")
	}

	if string(aes.Iv()) != hmI {
		panic("Iv does not match Hardware(iv)")
	}

	// Create a cypter service object - encryption/decryption
	c, _ := crypto.NewCrypter(
		[]byte(hmK),
		[]byte(hmI),
	)

	b1F, _  := helpers.ReadFile(extB1)
	hp1F, _ := helpers.ReadFile(config.HostPin1)

	d1, _ := c.Decrypt([]byte(b1F))
	if string(d1) != hp1F {
		panic("Pin1 does not match, invalid ext authentication!")
	}


	b2F, _  := helpers.ReadFile(extB2)
	hp2F, _ := helpers.ReadFile(config.HostPin2)

	d2, _ := c.Decrypt([]byte(b2F))
	if string(d2) != hp2F {
		panic("Pin2 does not match, invalid ext authentication!")
	}
}

func (b *BackendConfiguration) Welcome() {
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("- Compiler: %s\n", runtime.Compiler)
	fmt.Printf("- Runtime: %s\n", runtime.GOOS)
	fmt.Printf("- Go Arch: %s\n", runtime.GOARCH)
	fmt.Printf("- CPUs: %d\n", runtime.NumCPU())
	fmt.Println("----------------------------------------------------------------")
}
