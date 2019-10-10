package main

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"
)

const (

	// Public presentable keys
	HostMasterKeyPath 	= "/var/data/key"
	HostSerialPath 			= "/var/data/serial"
	ExtBase1Path   			= "var/data/pin"
	ExtBase2Path   			= "var/data/pin"

	// Private hidden keys
	PrivateMasterKeyPath = "/private/etc/key"
	PrivateBase1Path		 = "/private/etc/pin1"
	PrivateBase2Path 		 = "/private/etc/pin2"

)

type Keys struct {
	MasterKey string
	Pin1 string
	Pin2 string
	Serial string
}

// for string to struct implementations
var TypeRegistry = make(map[string]reflect.Type)

//go:generate moq -out cybric_test.go . Store
type Backend interface {
	Call(method string, path string, body interface{}) error
}

type BackendConfiguration struct {
	Config ConfigReader
	Logger *logrus.Logger
	Keys
}

func NewClient() *BackendConfiguration {
	c, err := LoadConfig(ConfigDefaults)
	if err != nil {
		panic(err)
	}

	return &BackendConfiguration{
		Config: c,
		Logger: LoadLogger(c),
		Keys: LoadKeys(),
	}
}

func main() {
	c := NewClient()

	e, _  := crypto.AvailableEntropy()

	c.Logger.Infof("Runtime: %s\n", runtime.GOOS)
	c.Logger.Infof("Entropy: %d\n", e)

	c.Logger.Infof("Serial: %s\n", c.Keys.Serial)
	c.Logger.Infof("MasterKey: %s\n", c.Keys.MasterKey)
	c.Logger.Infof("Pin1: %s\n", c.Keys.Pin1)
	c.Logger.Infof("Pin2: %s\n", c.Keys.Pin2)

	r,_ := crypto.GenerateRandomBytes(128)

	fmt.Println("BYTES:")
	fmt.Printf("%s\n", hex.Dump(r))

	fmt.Println("HEX:")
	fmt.Printf("%s\n", hex.EncodeToString(r))

	f := crypto.GenerateRandomFile(4096)
	fmt.Println("Generating random File: ", f)
}

func LoadKeys() (Keys) {
	var keys Keys

	var extB1, extB2 string

	if runtime.GOOS == "darwin" {
		extB1 = fmt.Sprintf("%s/%s", "/Volumes/BASE1", ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/Volumes/BASE2", ExtBase2Path)
	}

	paths := []string{
		HostSerialPath,
		HostMasterKeyPath,
		PrivateMasterKeyPath,
		PrivateBase1Path,
		PrivateBase2Path,
		extB1,
		extB2,
	}

	// Check all paths, ensure every one exists
	for _, v :=  range paths {
		if !helpers.FileExists(HostMasterKeyPath) {
			panic(fmt.Errorf("Missing [%s]", v))
		}
	}

	keys.Serial = helpers.ReadContents(HostSerialPath)

	// Create MasterKey from Host/Private
	masterHost := helpers.ReadContents(HostMasterKeyPath)
	masterPrivate := helpers.ReadContents(PrivateMasterKeyPath)

	keys.MasterKey = fmt.Sprintf("%s%s", masterHost, masterPrivate)

	// Create Pin1Key from Host/Private
	pin1Host := helpers.ReadContents(extB1)
	pin1Private := helpers.ReadContents(PrivateBase1Path)

	keys.Pin1 = fmt.Sprintf("%s%s", pin1Host, pin1Private)

	// Create Pin2Key from Host/Private
	pin2Host := helpers.ReadContents(extB2)
	pin2Private := helpers.ReadContents(PrivateBase2Path)

	keys.Pin2 = fmt.Sprintf("%s%s", pin2Host, pin2Private)

	return keys
}
