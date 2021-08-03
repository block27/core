package crypto

import (
	"bufio"
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
		"test":   "/dev/trandom",
		"darwin": "/dev/urandom",
		"linux":  "/dev/TrueRNG",
	}
)

// Reader - Main interface that can be passed to almost all Golang crypto
// implementations.
//
var Reader io.Reader

// init - initialize the Reader with the most effective system based
// rand generator.
//
func init() {
	Reader = &devReader{name: Devices["darwin"]}
}

// devReader - satisfies reads by reading the file named name.
//
type devReader struct {
	name string
	f    io.Reader
	mu   sync.Mutex
}

// Read - base read implementation for the reader. We here set our own rand
// device based on the init/os above.
//
func (r *devReader) Read(b []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		f, err := os.Open("/dev/TrueRNG")
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

var isEAGAIN func(error) bool

type hideAgainReader struct {
	r io.Reader
}

func (hr hideAgainReader) Read(p []byte) (n int, err error) {
	n, err = hr.r.Read(p)
	if err != nil && isEAGAIN != nil && isEAGAIN(err) {
		err = nil
	}

	return
}
