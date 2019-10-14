package main

import (
	// "encoding/hex"
	// "encoding/base64"
	"fmt"
	"reflect"
	"runtime"

	"github.com/Sirupsen/logrus"
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
)

// for string to struct implementations
var TypeRegistry = make(map[string]reflect.Type)

//go:generate moq -out cybric_test.go . Store
type Backend interface {
	Call(method string, path string, body interface{}) error
}

type BackendConfiguration struct {
	Config ConfigReader
	Logger *logrus.Logger
}

func NewClient() *BackendConfiguration {
	c, err := LoadConfig(ConfigDefaults)
	if err != nil {
		panic(err)
	}

	return &BackendConfiguration{
		Config: c,
		Logger: LoadLogger(c),
	}
}

func main() {
	// c := NewClient()

	LoadKeys()
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

func LoadKeys() {
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

	// Start encryption/decryption process
	c, _ := crypto.NewCrypter(
		[]byte(helpers.ReadFile(HostMasterKeyPath)),
		[]byte(helpers.ReadFile(HostMasterIvPath)),
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
