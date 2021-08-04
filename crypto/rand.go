package crypto

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

var (
	// Devices ... each OS we use will have a different PRNG device,
	// load based on OS.
	//
	Devices = map[string]string{
		"r": "/dev/random",
		"u": "/dev/urandom",
		"t": "/dev/TrueRNG",
	}
)

// Reader - Main interface that can be passed to almost all Golang crypto
// implementations.
var Reader io.Reader

// init - initialize the Reader with the most effective system based
// rand generator.
func init() {
	Reader = &devReader{name: Devices["u"]}
}

// devReader - satisfies reads by reading the file named name.
type devReader struct {
	name string
	f    io.Reader
	mu   sync.Mutex
}

type hideAgainReader struct {
	r io.Reader
}

var isEAGAIN func(error) bool

// Read - base read implementation for the reader. We here set our own rand
// device based on the init/os above.
func (r *devReader) Read(b []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		if os.Getenv("RNG_DEVICE_PATH") != "" {
			r.name = os.Getenv("RNG_DEVICE_PATH")
		}
		
		fmt.Println("#block27/core/crypto : Read() using device: ", r.name)
		
		f, err := os.Open(r.name)
		if f == nil {
			return 0, err
		}

		if runtime.GOOS == "plan9" {
			r.f = f
		} else {
			r.f = bufio.NewReader(hideAgainReader{f})
		}
	}

	return r.f.Read(b)
}

func (hr hideAgainReader) Read(p []byte) (n int, err error) {
	n, err = hr.r.Read(p)

	if err != nil && isEAGAIN != nil && isEAGAIN(err) {
		err = nil
	}

	return
}
