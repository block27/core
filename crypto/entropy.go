package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/amanelis/core-zero/helpers"
)

// MinimumEntropy is the minimum amount of entropy that will be considered safe.
// Set this to what you consider to be a 'safe' minimum entropy amount (in bits)
var MinimumEntropy = 256

// Timeout sets the maximum amount of time to wait for entropy.
// Waiting for entropy will time out after this amount of time. Setting to zero will never time out.
var Timeout = time.Second * 10

// The only supported OS is linux at this time.
var supportedOS = "linux"

// ErrTimeout is for when the system waits too long and gives up
var ErrTimeout = errors.New("timed out waiting for sufficient entropy")

// ErrUnsupportedOS is for for an invalid OS that does not provide entropy estimates
var ErrUnsupportedOS = errors.New("unsupported OS. Only Linux is supported")

const (
	// EntropyAvail ...
	EntropyAvail = "/proc/sys/kernel/random/entropy_avail"

	// PoolSize ...
	PoolSize     = "/proc/sys/kernel/random/poolsize"
)

// EntropyAPI ...
type EntropyAPI interface {
	EntropyAvail() (int, error)
	PoolSize() (int, error)
	GenerateRandomBytes(size int) ([]byte, error)
	GenerateRandomFile(size int) (string, error)
	Ping() (string, error)
	WaitForEntropy() error
}

type entropyAPI struct{}

// NewEntropy ...
func NewEntropy() EntropyAPI {
	return &entropyAPI{}
}

// PoolSize ...
func (e *entropyAPI) PoolSize() (int, error) {
	return 0, nil
}

// EntropyAvail ...
func (e *entropyAPI) EntropyAvail() (int, error) {
	if runtime.GOOS != supportedOS || !helpers.FileExists(EntropyAvail) {
		return -1, fmt.Errorf("Invalid architecture for running hwrng, found system: %s", runtime.GOOS)
	}

	cmd := exec.Command("/bin/cat", EntropyAvail)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return -1, fmt.Errorf("function AvailableEntropy() exec failed with: %s", err)
	}

	value, err := strconv.Atoi(strings.TrimSuffix(string(stdout.Bytes()), "\n"))
	if err != nil {
		return -1, fmt.Errorf("function AvailableEntropy() strconv failed with: %s", err)
	}

	return value, nil
}

// GenerateRandomBytes ...
func (e *entropyAPI) GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)

	if _, err := Reader.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomFile ...
func (e *entropyAPI) GenerateRandomFile(size int) (string, error) {
	filename := fmt.Sprintf("/tmp/%s", strconv.Itoa(int(time.Now().Unix())))

	if _, err := os.Create(filename); err != nil {
		return "", err
	}

	randomBy, err := e.GenerateRandomBytes(size)
	if err != nil {
		return "", err
	}

	if err := ioutil.WriteFile(filename, randomBy, 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// Ping ...
func (e *entropyAPI) Ping() (string, error) {
	return "pong", nil
}

// WaitForEntropy blocks until sufficient entropy is available
func (e *entropyAPI) WaitForEntropy() error {
	if runtime.GOOS != supportedOS {
		return ErrUnsupportedOS
	}

	// set up the timeout
	timeout := make(chan bool, 1)
	if Timeout != 0 {
		go func(timeoutDuration time.Duration) {
			time.Sleep(timeoutDuration)
			timeout <- true
		}(Timeout)
	}

	for {
		entropy, err := e.EntropyAvail()

		switch {
		case err != nil:
			return err
		case entropy > MinimumEntropy:
			return nil
		default:
			select {
			case <-timeout:
				return ErrTimeout
			default:
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}
