package main

import (
	// "encoding/hex"
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
	HostPin1						= "/var/data/pin1"
	HostPin2 						= "/var/data/pin2"
	HostSerialPath 			= "/var/data/serial"

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

	// Initialize new crypter struct. Errors are ignored.
	crypter, _ := crypto.NewCrypter(
		[]byte(helpers.ReadFile(HostMasterKeyPath)),
		[]byte(helpers.ReadFile(HostMasterIvPath)),
	)


	fmt.Println("PIN1 path: ", extB1)
	ePin1 := helpers.ReadBinary(extB1)
	fmt.Printf("pin1 e: %v\n", ePin1)
	dPin1, _ := crypter.Decrypt(ePin1)
  fmt.Printf("pin1 d: %v\n", dPin1)


	hPin1 := helpers.ReadFile(HostPin1)
	hPin2 := helpers.ReadFile(HostPin2)

	fmt.Println("PIN1: ", hPin1)
	fmt.Println("PIN2: ", hPin2)

	// if hPin1 != string(dPin1) {
	// 	fmt.Printf("pin1 is not valid\n")
	// }

	//
	// // Create MasterKey from Host/Private
	// masterHost := helpers.ReadContents(HostMasterKeyPath)
	// masterPrivate := helpers.ReadContents(PrivateMasterKeyPath)
	//
	// keys.MasterKey = fmt.Sprintf("%s%s", masterHost, masterPrivate)
	//
	// // Create Pin1Key from Host/Private
	// pin1Host := helpers.ReadContents(extB1)
	// pin1Private := helpers.ReadContents(PrivateBase1Path)
	//
	// keys.Pin1 = fmt.Sprintf("%s%s", pin1Host, pin1Private)
	//
	// // Create Pin2Key from Host/Private
	// pin2Host := helpers.ReadContents(extB2)
	// pin2Private := helpers.ReadContents(PrivateBase2Path)
	//
	// keys.Pin2 = fmt.Sprintf("%s%s", pin2Host, pin2Private)

}
