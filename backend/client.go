package backend

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"runtime"

	// "strconv"
	"strings"
	"time"

	"github.com/amanelis/core-zero/config"
	"github.com/amanelis/core-zero/crypto"
	h "github.com/amanelis/core-zero/helpers"
	"github.com/amanelis/core-zero/services/bbolt"
	"github.com/amanelis/core-zero/services/serial"

	"github.com/awnumar/memguard"
	"github.com/briandowns/spinner"
	"github.com/google/gousb"
	"github.com/sirupsen/logrus"
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

// device - capture data in from connected AES/Arduino usbmodem
type device struct {
	Product      uint16 `json:"product"`
	Vendor       uint16 `json:"vendor"`
	Serial       string `json:"serial"`
	Manufacturer string `json:"manufacturer"`
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

	bDb, err := bbolt.NewDB(fmt.Sprintf("%s/botldb", c.GetString("paths.base")))
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
	spinners, err := newSpinner(3)
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
	aes, err := b.requestHardwareKeys()
	if err != nil {
		for i := 0; i < len(spinners); i++ {
			spinners[i].Stop()
		}
		return err
	}

	hmK, _ := h.ReadFile(config.HostMasterKeyPath)
	hmI, _ := h.ReadFile(config.HostMasterIvPath)

	// ---------------------------------------------------------------------------
	kVal, aesErr := aes.Key().Open()
	if aesErr != nil {
		fmt.Println(aesErr)
		return fmt.Errorf("invalid memory decryption on AES[key]")
	}
	defer kVal.Destroy()
	kVal.Melt()

	if string(kVal.Bytes()) != hmK {
		for i := 0; i < len(spinners); i++ {
			spinners[i].Stop()
		}

		fmt.Printf("key: %s, val: %s\n", string(kVal.Bytes()), hmK)

		return fmt.Errorf("%s", h.RFgB("key does not match Hardware(key)"))
	}
	// kLen := len(string(kVal.Bytes()))

	// ---------------------------------------------------------------------------
	iVal, aesErr := aes.Iv().Open()
	if aesErr != nil {
		return fmt.Errorf("invalid memory decryption on AES[iv]")
	}
	defer iVal.Destroy()
	iVal.Melt()

	if string(iVal.Bytes()) != hmI {
		for i := 0; i < len(spinners); i++ {
			spinners[i].Stop()
		}
		return fmt.Errorf("%s", h.RFgB("iv does not match Hardware(iv)"))
	}
	// iLen := len(string(iVal.Bytes()))

	for i := 0; i < len(spinners); i++ {
		spinners[i].Stop()
	}

	// fmt.Printf("hw ky(%d) verified, %s\n", kLen, h.GFgB("OK"))
	// fmt.Printf("hw iv(%d) verified, %s\n", iLen, h.GFgB("OK"))

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

func findMPD26(product, vendor uint16) func(desc *gousb.DeviceDesc) bool {
	return func(desc *gousb.DeviceDesc) bool {
		return desc.Product == gousb.ID(product) && desc.Vendor == gousb.ID(vendor)
	}
}

// locateDevice ... temporary fix, but need to  find the AES device to  starts
func (b *Backend) locateDevice() (string, error) {
	data, err := ioutil.ReadDir("/dev")
	if err != nil {
		return "", err
	}

	// Run device identification process
	// Open our jsonFile
	f, err := h.NewFile("/var/data/device")
	if err != nil {
		return "", err
	}

	var d device

	// Unmarshall data into struct var
	jerr := json.Unmarshal([]byte(string(f.GetBody())), &d)
	if jerr != nil {
		return "", fmt.Errorf(h.RFgB("invalid device mapping file"))
	}

	ctx := gousb.NewContext()
	devices, _ := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		fmt.Printf("desc.Product: %s\n", desc.Product)
		fmt.Printf("desc.Vendor: %s\n", desc.Vendor)
		fmt.Printf("gousb.ID(d.Product): %s\n", gousb.ID(d.Product))
		fmt.Printf("gousb.ID(d.Vendor): %s\n", gousb.ID(d.Vendor))

		return desc.Product == gousb.ID(d.Product) && desc.Vendor == gousb.ID(d.Vendor)
	})

	if len(devices) == 0 {
		return "", fmt.Errorf(h.RFgB("invalid authentication device"))
	}

	m, _ := devices[0].Manufacturer()
	s, _ := devices[0].SerialNumber()

	if m != d.Manufacturer || s != d.Serial {
		return "", fmt.Errorf(h.RFgB("device manufacturer and serial did not match"))
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
		if strings.Contains(f.Name(), "ttyS1") {
			return fmt.Sprintf("/dev/%s", f.Name()), nil
		}
	}

	return "", nil
}

// requestHardwareKeys ...
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
func (b *Backend) requestHardwareKeys() (*crypto.AESCredentialsEnclave, error) {
	dev, err := b.locateDevice()
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
		Method: "k.Request.hex32\r",
		Size:   32,
	})

	if ke != nil {
		return nil, ke
	}

	// Hold the key in an enclave
	kyEn := memguard.NewEnclave([]byte(ky))
	ky, ke = nil, nil

	// Request IV
	iv, ie := c.Request(serial.Request{
		Method: "i.Request.hex16\r",
		Size:   16,
	})

	if ie != nil {
		return nil, ie
	}

	// Hold the iv in an enclave
	ivEn := memguard.NewEnclave([]byte(iv))
	iv, ie = nil, nil

	aes, err := crypto.NewAESCredentialsEnclave(kyEn, ivEn)
	if err != nil {
		return nil, err
	}

	return aes, nil
}

// Welcome - prints a nice welcome message with some info on environment
func (b *Backend) Welcome() {
	dev, err := b.locateDevice()
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

	// minF, maxF := 0, len(f)-1
	minC, maxC := 0, len(h.Colors)-1

	for i := 0; i < num; i++ {
		// ndxFnt := rand.Intn(maxF-minF+1) + minF
		ndxCol := rand.Intn(maxC-minC+1) + minC

		s := spinner.New(spinner.CharSets[11], 75*time.Millisecond)
		s.Color(h.Colors[ndxCol], "bold")

		spinners = append(spinners, s)
	}

	return spinners, nil
}
