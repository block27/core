package crypto

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/amanelis/bespin/helpers"
)

const (
	EntropyAvail = "/proc/sys/kernel/random/entropy_avail"
	PoolSize     = "/proc/sys/kernel/random/poolsize"
)

type EntropyAPI interface {
	EntropyAvail() (int, error)
	PoolSize() (int, error)
	GenerateRandomBytes(size int) ([]byte, error)
	GenerateRandomFile(size int) (string, error)
	Ping() (string, error)
}

type entropyAPI struct{}

func NewEntropy() EntropyAPI {
	return &entropyAPI{}
}

func (e *entropyAPI) PoolSize() (int, error) {
	return 0, nil
}

func (e *entropyAPI) EntropyAvail() (int, error) {
	if runtime.GOOS != "linux" || !helpers.FileExists(EntropyAvail) {
		return -1, fmt.Errorf("Invalid architecture for running hwrng, found system: %s", runtime.GOOS)
	}

	cmd := exec.Command("/bin/cat", EntropyAvail)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return -1, fmt.Errorf("AvailableEntropy() exec failed with: %s\n", err)
	}

	content := strings.TrimSuffix(string(stdout.Bytes()), "\n")

	value, err := strconv.Atoi(content)
	if err != nil {
		return -1, fmt.Errorf("AvailableEntropy() strconv failed with: %s\n", err)
	}

	return value, nil
}

func (e *entropyAPI) GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)

	// if _, err := Reader.Read(b); err != nil {
	// 	return nil, err
	// }

	return b, nil
}

func (e *entropyAPI) GenerateRandomFile(size int) (string, error) {
	filename := fmt.Sprintf("/tmp/%s", strconv.Itoa(int(time.Now().Unix())))

	if _, err := os.Create(filename); err != nil {
		return "", err
	}

	randomBy, _ := e.GenerateRandomBytes(size)

	if err := ioutil.WriteFile(filename, randomBy, 0644); err != nil {
		panic(err)
	}

	return filename, nil
}

func (e *entropyAPI) Ping() (string, error) {
	return "pong", nil
}
