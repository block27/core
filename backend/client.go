package backend

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"runtime"
	"strings"
	"time"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	h "github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/bbolt"
	"github.com/amanelis/bespin/services/serial"

	"github.com/briandowns/spinner"
	"github.com/sirupsen/logrus"
)

var (
	// AESDevice - crypto key/iv provider.
	//
	AESDeviceMac = "/dev/tty.usbmodem20021401"
	AESDeviceArm = "/dev/ttyACM0"
)

// Backend - main struct for the entire application configuration
type Backend struct {
	// C - contains the yaml file configuration key/values and other env specifics
	C *config.Reader

	// D - the main connector to BBoltDB via services/bbolt
	D bbolt.Datastore

	// L - a logrus logger, customized for this application
	L *logrus.Logger
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// NewBackend - factory method for producing a new type of Backend
func NewBackend() (*Backend, error) {
	c, err := config.LoadConfig(config.Defaults)
	if err != nil {
		return nil, err
	}

	bDb, err := bbolt.NewDB("/tmp/botldb")
	if err != nil {
		return nil, err
	}

	// Base BackendConfiguration to link structs and objects
	var bc = &Backend{
		C: &c,
		D: bDb,
		L: config.LoadLogger(c),
	}

	return bc, nil
}

// HardwareAuthenticate ...
//
// A Key/Iv will be stored on the hardware device itself. These two values
// are used to encrypt the two pins stored in the ext volumes [BASE1, BASE2]
//
// These values decrypted must match the two  pins stored on the hardware to
// work, if removed or altered, HSM  code will  not run. But key recovery is
// still possible.
func (b *Backend) HardwareAuthenticate() error {
	spinners, err := newSpinner(6)
	if err != nil {
		return err
	}

	fmt.Printf("Begining AES hardware authentication...\n")

	for i := 0; i < len(spinners); i++ {
		go spinners[i].Start()
	}

	var extB1, extB2 string

	if runtime.GOOS == "darwin" {
		extB1 = fmt.Sprintf("%s/%s", "/Volumes/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/Volumes/BASE2", config.ExtBase2Path)
	} else if runtime.GOOS == "linux" {
		extB1 = fmt.Sprintf("%s/%s", "/media/pi/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/media/pi/BASE2", config.ExtBase2Path)
	} else {
		for i := 0; i < len(spinners); i++ {
			spinners[i].Stop()
		}
		return fmt.Errorf("unsupported OS")
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
			for i := 0; i < len(spinners); i++ {
				spinners[i].Stop()
			}
			return fmt.Errorf("%s%s%s", h.RFgB("missing ["), h.RFgB(v), h.RFgB("] mount"))
		}
	}

	// Pull the Key/Iv off the hardware device
	aes, err := b.RequestHardwareKeys()
	if err != nil {
		for i := 0; i < len(spinners); i++ {
			spinners[i].Stop()
		}
		return err
	}

	hmK, _ := h.ReadFile(config.HostMasterKeyPath)
	hmI, _ := h.ReadFile(config.HostMasterIvPath)

	if string(aes.Key()) != hmK {
		for i := 0; i < len(spinners); i++ {
			spinners[i].Stop()
		}
		return fmt.Errorf("%s", h.RFgB("key does not match Hardware(key)"))
	}

	if string(aes.Iv()) != hmI {
		for i := 0; i < len(spinners); i++ {
			spinners[i].Stop()
		}
		return fmt.Errorf("%s", h.RFgB("iv does not match Hardware(iv)"))
	}

	for i := 0; i < len(spinners); i++ {
		spinners[i].Stop()
	}
	fmt.Printf("hw ky(%d) verified, %s\n", len(string(aes.Key())), h.GFgB("OK"))
	fmt.Printf("hw iv(%d) verified, %s\n", len(string(aes.Iv())), h.GFgB("OK"))

	// Create a cypter service object - encryption/decryption
	c, _ := crypto.NewCrypter(
		[]byte(hmK),
		[]byte(hmI),
	)

	// Read ext1
	b1F, _ := h.ReadFile(extB1)
	p1F, _ := h.ReadFile(config.HostPin1)

	dec1, _ := c.Decrypt([]byte(b1F))
	if string(dec1) != p1F {
		return fmt.Errorf("%s", h.RFgB("pin1 does not match, invalid ext authentication"))
	}

	// Read ext2
	b2F, _ := h.ReadFile(extB2)
	p2F, _ := h.ReadFile(config.HostPin2)

	dec2, _ := c.Decrypt([]byte(b2F))
	if string(dec2) != p2F {
		return fmt.Errorf("%s", h.RFgB("pin2 does not match, invalid ext authentication"))
	}

	return nil
}

// LocateDevice ... temporary fix, but need to  find the AES device to  starts
func (b *Backend) LocateDevice() (string, error) {
	data, err := ioutil.ReadDir("/dev")
	if err != nil {
		return "", err
	}

	for _, f := range data {
		// MacOSX
		if strings.Contains(f.Name(), "tty.usbmodem") {
			return fmt.Sprintf("/dev/%s", f.Name()), nil
		}

		// linux based OS
		if strings.Contains(f.Name(), "ttyACM0") {
			return fmt.Sprintf("/dev/%s", f.Name()), nil
		}

		// arm based OS
		if strings.Contains(f.Name(), "ttyGS0") {
			return fmt.Sprintf("/dev/%s", f.Name()), nil
		}
	}

	return "", nil
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
func (b *Backend) RequestHardwareKeys() (*crypto.AESCredentials, error) {
	dev, err := b.LocateDevice()
	if err != nil {
		return nil, err
	}

	if !h.FileExists(dev) {
		return nil, fmt.Errorf("%s",
			h.RFgB("missing hardware AES device, cannot continue"))
	}

	c := serial.NewSerial(dev, 115200)

	// Request KEY
	ky, ke := c.Request(serial.Request{
		Method: "k.Request.byte32\r",
		Size:   32,
	})

	if ke != nil {
		return nil, ke
	}

	// Request IV
	iv, ie := c.Request(serial.Request{
		Method: "i.Request.byte16\r",
		Size:   16,
	})

	if ie != nil {
		return nil, ie
	}

	aes, err := crypto.NewAESCredentials(ky, iv)
	if err != nil {
		return nil, err
	}

	return aes, nil
}

// Welcome - prints a nice welcome message with some info on environment
func (b *Backend) Welcome() {
	dev, err := b.LocateDevice()
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n",
		h.CFgB("----------------------------------------------------------------"))
	fmt.Printf("%s: \t%s\n", h.GFgB("- Arch"), h.WFgB(runtime.GOARCH))
	fmt.Printf("%s: \t%s\n", h.GFgB("- AES DEV"), h.WFgB(dev))
	fmt.Printf("%s: \t%s\n", h.GFgB("- Compiler"), h.WFgB(runtime.Compiler))
	fmt.Printf("%s: \t%s\n", h.GFgB("- CPUS"), h.WFgB(runtime.NumCPU()))
	fmt.Printf("%s: \t%s\n", h.GFgB("- Crypto"), h.WFgB(crypto.Devices[runtime.GOOS]))
	fmt.Printf("%s: \t%s\n", h.GFgB("- Runtime"), h.WFgB(runtime.GOOS))
	fmt.Printf("%s: \t%s\n", h.GFgB("- Mode"), h.WFgB("dev"))

	fmt.Printf("%s: \t%s\n", h.GFgB("- EntropyA"), h.WFgB(0))
	fmt.Printf("%s: \t%s\n", h.GFgB("- EntropyP"), h.WFgB(0))
	fmt.Printf("%s\n",
		h.CFgB("----------------------------------------------------------------"))
}

func newSpinner(num int) ([]*spinner.Spinner, error) {
	f := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 14, 17, 18, 19, 20, 21, 22, 23, 24, 28, 29, 30, 40, 41, 42}

	if num > len(f) {
		return nil, fmt.Errorf("out of range from formats selected, please try smaller number")
	}

	var spinners []*spinner.Spinner

	minF, maxF := 0, len(f)-1
	minC, maxC := 0, len(h.Colors)-1

	for i := 0; i < num; i++ {

		ndxFnt := rand.Intn(maxF-minF+1) + minF
		ndxCol := rand.Intn(maxC-minC+1) + minC

		s := spinner.New(spinner.CharSets[ndxFnt], 75*time.Millisecond)
		s.Color(h.Colors[ndxCol], "bold")

		spinners = append(spinners, s)

	}

	return spinners, nil
}
