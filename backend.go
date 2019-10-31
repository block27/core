package main

import (
	"fmt"
	"runtime"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	h "github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/bbolt"
	"github.com/amanelis/bespin/services/serial"
	"github.com/sirupsen/logrus"
)

// BackendConfiguration - main struct for the entire application configuration
type BackendConfiguration struct {
	// C - contains the yaml file configuration key/values and other env specifics
	C *config.ConfigReader

	// D - the main connector to BBoltDB via services/bbolt
	D bbolt.Datastore

	// L - a logrus logger, customized for this application
	L *logrus.Logger
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
	c := serial.NewSerial("/dev/tty.usbmodem2002140", 115200)

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

	b.L.Infof("ky(%d) verified, %s", len(string(ky)), h.GreenFgD("OK"))
	b.L.Infof("iv(%d) verified, %s", len(string(iv)), h.GreenFgD("OK"))

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
		if !h.FileExists(v) {
			return fmt.Errorf("Missing [%s]", v)
		}
	}

	// Pull the Key/Iv off the hardware device
	aes, err := b.RequestHardwareKeys()
	if err != nil {
		return err
	}

	hmK, _ := h.ReadFile(config.HostMasterKeyPath)
	hmI, _ := h.ReadFile(config.HostMasterIvPath)

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
	b1F, _ := h.ReadFile(extB1)
	hp1F, _ := h.ReadFile(config.HostPin1)

	dec1, _ := c.Decrypt([]byte(b1F))
	if string(dec1) != hp1F {
		return fmt.Errorf("Pin1 does not match, invalid ext authentication!")
	}

	// Read ext2
	b2F, _ := h.ReadFile(extB2)
	hp2F, _ := h.ReadFile(config.HostPin2)

	dec2, _ := c.Decrypt([]byte(b2F))
	if string(dec2) != hp2F {
		return fmt.Errorf("Pin2 does not match, invalid ext authentication!")
	}

	return nil
}

func (b *BackendConfiguration) Welcome() {
	fmt.Printf("%s\n", h.CyanFgB("----------------------------------------------------------------"))
	fmt.Printf("%s: %d\n", h.GreenFgB("- CPUs"), runtime.NumCPU())
	fmt.Printf("%s: %s\n", h.GreenFgB("- Arch"), runtime.GOARCH)
	fmt.Printf("%s: %s\n", h.GreenFgB("- Compiler"), runtime.Compiler)
	fmt.Printf("%s: %s\n", h.GreenFgB("- Runtime"), runtime.GOOS)
	fmt.Printf("%s\n", h.CyanFgB("----------------------------------------------------------------"))
}
