package main

import (
	// "encoding/hex"
	// "encoding/base64"
	"fmt"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/tarm/serial"  // github.com/jacobsa/go-serial/serial

	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"
)

const (
	HostMasterKeyPath 	= "/var/data/key"
	HostMasterIvPath 		= "/var/data/iv"
	HostSerialPath 			= "/var/data/serial"

	HostPin1						= "/var/data/pin1"
	HostPin2 						= "/var/data/pin2"

	ExtBase1Path   			= "var/data/pin"
	ExtBase2Path   			= "var/data/pin"

	Configuration 			= "/var/data/config"
)

type BackendConfiguration struct {
	Config ConfigReader
	Logger *logrus.Logger
}

func NewClient() (*BackendConfiguration, error) {
	c, err := LoadConfig(ConfigDefaults)
	if err != nil {
		panic(err)
	}

	var bc = &BackendConfiguration{
		Config: c,
		Logger: LoadLogger(c),
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
func (b *BackendConfiguration) SerialFPGAHardwareKeys() (*crypto.AESCredentials) {
	c := &serial.Config{Name: "/dev/tty.usbmodem20021401", Baud: 115200}

	s, err := serial.OpenPort(c)
  if err != nil {
  	panic(err)
  }

	defer s.Close()

	ky, err := s.Write([]byte("k.Request.byte32\r"))
  if err != nil {
		panic(err)
  }

	bkS := 32
	bky := make([]byte, bkS)
  ky, err = s.Read(bky)
  if err != nil {
  	panic(err)
  }

	iv, err := s.Write([]byte("i.Request.byte16\r"))
	if err != nil {
		panic(err)
	}

	biS := 16
	biv := make([]byte, biS)
	iv, err = s.Read(biv)
	if err != nil {
		panic(err)
	}

	kyS := string(bky[:ky])
	ivS := string(biv[:iv])

	kSz := len(kyS)
	iSz := len(ivS)

	if kSz != bkS {
		panic("Key size did not match, cannot read serial values")
	}

	if iSz != biS {
		panic("Iv size did not match, cannot read serial values")
	}

	fmt.Printf("ky(%d) OK\n", kSz)
	fmt.Printf("iv(%d) OK\n", iSz)

	aes, err := crypto.NewAESCredentials(bky[:ky], biv[:iv])
	if err != nil {
		panic(err)
	}

	return aes
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
		extB1 = fmt.Sprintf("%s/%s", "/Volumes/BASE1", ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/Volumes/BASE2", ExtBase2Path)
	} else if runtime.GOOS == "linux" {
		extB1 = fmt.Sprintf("%s/%s", "/media/pi/BASE1", ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/media/pi/BASE2", ExtBase2Path)
	} else {
		panic("Unsupported OS")
	}

	paths := []string{
		HostMasterKeyPath,
		HostMasterIvPath,
		HostPin1,
		HostPin2,
		HostSerialPath,
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
	aes := b.SerialFPGAHardwareKeys()

	hmK, _ := helpers.ReadFile(HostMasterKeyPath)
	hmI, _ := helpers.ReadFile(HostMasterIvPath)

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
	hp1F, _ := helpers.ReadFile(HostPin1)

	d1, _ := c.Decrypt([]byte(b1F))
	if string(d1) != hp1F {
		panic("Pin1 does not match, invalid ext authentication!")
	}


	b2F, _  := helpers.ReadFile(extB2)
	hp2F, _ := helpers.ReadFile(HostPin2)

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
