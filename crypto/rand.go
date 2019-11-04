package crypto

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"sync"
)

var (
	devices = map[string]string{
		"test": "/dev/trandom",
		"darwin": "/dev/urandom",
		"linux":  "/dev/TrueRNG",
	}
)

var Reader io.Reader

func init() {
	Reader = &devReader{name: devices[runtime.GOOS]}
}

// devReader - satisfies reads by reading the file named name.
type devReader struct {
	name string
	f    io.Reader
	mu   sync.Mutex
	used int32
}

// Read ...
// func (r *devReader) Read(buf []byte) (n int, err error) {
// 	return 0, nil
// }

func (r *devReader) Read(b []byte) (n int, err error) {
	// if atomic.CompareAndSwapInt32(&r.used, 0, 1) {
	// 	// First use of randomness. Start timer to warn about
	// 	// being blocked on entropy not being available.
	// 	t := time.AfterFunc(60*time.Second, warnBlocked)
	// 	defer t.Stop()
	// }
	// if altGetRandom != nil && r.name == urandomDevice && altGetRandom(b) {
	// 	return len(b), nil
	// }

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
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

var altGetRandom func([]byte) (ok bool)
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
