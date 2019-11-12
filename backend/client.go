package backend

import (
	"fmt"
	"math/rand"
	"runtime"
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
	AESDevice = "/dev/tty.usbmodem20021401"
)

// Backend - main struct for the entire application configuration
type Backend struct {
	// C - contains the yaml file configuration key/values and other env specifics
	C *config.ConfigReader

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
	c, err := config.LoadConfig(config.ConfigDefaults)
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
	if !h.FileExists(AESDevice) {
		return nil, fmt.Errorf("%s",
			h.RedFgB("missing hardware AES device, cannot continue"))
	}

	c := serial.NewSerial(AESDevice, 115200)

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

// ValidateKeys ...
//
// A Key/Iv will be stored on the hardware device itself. These two values
// are used to encrypt the two pins stored in the ext volumes [BASE1, BASE2]
//
// These values decrypted must match the two  pins stored on the hardware to
// work, if removed or altered, HSM  code will  not run. But key recovery is
// still possible.
func (b *Backend) ValidateKeys() error {
	s := newSpinner()
	s.Start()

	fmt.Printf("Begining AES hardware authentication...\n")

	var extB1, extB2 string

	if runtime.GOOS == "darwin" {
		extB1 = fmt.Sprintf("%s/%s", "/Volumes/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/Volumes/BASE2", config.ExtBase2Path)
	} else if runtime.GOOS == "linux" {
		extB1 = fmt.Sprintf("%s/%s", "/media/pi/BASE1", config.ExtBase1Path)
		extB2 = fmt.Sprintf("%s/%s", "/media/pi/BASE2", config.ExtBase2Path)
	} else {
		s.Stop()
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
			s.Stop()
			return fmt.Errorf("%s%s%s", h.RedFgB("missing ["), h.RedFgB(v), h.RedFgB("] mount"))
		}
	}

	// Pull the Key/Iv off the hardware device
	aes, err := b.RequestHardwareKeys()
	if err != nil {
		s.Stop()
		return err
	}

	hmK, _ := h.ReadFile(config.HostMasterKeyPath)
	hmI, _ := h.ReadFile(config.HostMasterIvPath)

	if string(aes.Key()) != hmK {
		s.Stop()
		return fmt.Errorf("%s", h.RedFgB("key does not match Hardware(key)"))
	}

	if string(aes.Iv()) != hmI {
		s.Stop()
		return fmt.Errorf("%s", h.RedFgB("iv does not match Hardware(iv)"))
	}

	s.Stop()
	fmt.Printf("hw ky(%d) verified, %s\n", len(string(aes.Key())), h.GreenFgB("OK"))
	fmt.Printf("hw iv(%d) verified, %s\n", len(string(aes.Iv())), h.GreenFgB("OK"))

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
		return fmt.Errorf("%s", h.RedFgB("pin1 does not match, invalid ext authentication"))
	}

	// Read ext2
	b2F, _ := h.ReadFile(extB2)
	p2F, _ := h.ReadFile(config.HostPin2)

	dec2, _ := c.Decrypt([]byte(b2F))
	if string(dec2) != p2F {
		return fmt.Errorf("%s", h.RedFgB("pin2 does not match, invalid ext authentication"))
	}

	return nil
}

// Welcome - prints a nice welcome message with some info on environment
func (b *Backend) Welcome() {
	fmt.Printf("%s\n",
		h.CyanFgB("----------------------------------------------------------------"))
	fmt.Printf("%s: \t%s\n", h.GreenFgB("- Arch"), h.WhiteFgB(runtime.GOARCH))
	fmt.Printf("%s: \t%s\n", h.GreenFgB("- Compiler"), h.WhiteFgB(runtime.Compiler))
	fmt.Printf("%s: \t%s\n", h.GreenFgB("- CPUS"), h.WhiteFgB(runtime.NumCPU()))
	fmt.Printf("%s: \t%s\n", h.GreenFgB("- Crypto"), h.WhiteFgB(crypto.Devices[runtime.GOOS]))
	fmt.Printf("%s: \t%s\n", h.GreenFgB("- Runtime"), h.WhiteFgB(runtime.GOOS))
	fmt.Printf("%s: \t%s\n", h.GreenFgB("- Mode"), h.WhiteFgB("dev"))

	fmt.Printf("%s: \t%s\n", h.GreenFgB("- EntropyA"), h.WhiteFgB(0))
	fmt.Printf("%s: \t%s\n", h.GreenFgB("- EntropyP"), h.WhiteFgB(0))
	fmt.Printf("%s\n",
		h.CyanFgB("----------------------------------------------------------------"))
}

func newSpinner() *spinner.Spinner {
	s := spinner.New(spinner.CharSets[11], 75*time.Millisecond)

	min, max := 0, len(h.Colors)-1
	ndxCol := rand.Intn(max-min+1) + min

	s.Color(h.Colors[ndxCol], "bold")

	return s
}
