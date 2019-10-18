package main

import (
	// "encoding/hex"
	// "encoding/base64"
	"fmt"
	"reflect"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/tarm/serial"

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

// for string to struct implementations
var TypeRegistry = make(map[string]reflect.Type)

type BackendConfiguration struct {
	Config ConfigReader
	Logger *logrus.Logger
}

func NewClient() *BackendConfiguration {
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

	return bc
}

func main() {
	// Initalize a new client, the base entrpy point to the application code
	c := NewClient()

	// Check and ensure correct USB/serial peripherals have correct authentication
	c.ValidateKeys()

	// c.
	//
	// e, _  := crypto.AvailableEntropy()
	//
	// c.Logger.Infof("Runtime: %s", runtime.GOOS)
	// c.Logger.Infof("Entropy: %d", e)

	// r,_ := crypto.GenerateRandomBytes(128)
	//
	// fmt.Println("")
	// fmt.Println("BYTES:")
	// fmt.Printf("%s\n", hex.Dump(r))
	//
	// fmt.Println("HEX:")
	// fmt.Printf("%s\n", hex.EncodeToString(r))
	//
	// f := crypto.GenerateRandomFile(4096)
	// fmt.Println("Generating random File: ", f)
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
func (b *BackendConfiguration) USBFPGAHardwareKeys() (*crypto.AESCredentials) {
	c := &serial.Config{Name: "/dev/tty.usbmodem20021401", Baud: 115200}

	s, err := serial.OpenPort(c)
  if err != nil {
  	panic(err)
  }

	ky, err := s.Write([]byte("k.Request.byte32\r"))
  if err != nil {
		panic(err)
  }

	bky := make([]byte, 32)
  ky, err = s.Read(bky)
  if err != nil {
  	panic(err)
  }

	iv, err := s.Write([]byte("i.Request.byte16\r"))
	if err != nil {
		panic(err)
	}

	biv := make([]byte, 16)
	iv, err = s.Read(biv)
	if err != nil {
		panic(err)
	}

	var kyS, ivS string
	kyS = string(bky[:ky])
	ivS = string(biv[:iv])

	fmt.Printf("ky(%d): %s\n", len(kyS), kyS)
	fmt.Printf("iv(%d): %s\n", len(ivS), ivS)

	return &crypto.AESCredentials{Key: bky[:ky], Iv: biv[:iv]}
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
		if !helpers.FileExists(HostMasterKeyPath) {
			panic(fmt.Errorf("Missing [%s]", v))
		}
	}

	aes := b.USBFPGAHardwareKeys()

	hmK := helpers.ReadFile(HostMasterKeyPath)
	hmI := helpers.ReadFile(HostMasterIvPath)

	if string(aes.Key) != hmK {
		panic("Key does not match Hardware(key)")
	}

	if string(aes.Iv) != hmI {
		panic("Iv does not match Hardware(iv)")
	}

	c, _ := crypto.NewCrypter(
		[]byte(hmK),
		[]byte(hmI),
	)

	d1, _ := c.Decrypt([]byte(helpers.ReadFile(extB1)))
	if string(d1) != helpers.ReadFile(HostPin1) {
		panic("Pin1 does not match, invalid ext authentication!")
	}

	d2, _ := c.Decrypt([]byte(helpers.ReadFile(extB2)))
	if string(d2) != helpers.ReadFile(HostPin2) {
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
