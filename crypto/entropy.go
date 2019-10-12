package crypto

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"strconv"
	"time"

	"github.com/amanelis/bespin/helpers"
)

const (
	EntropyAvail = "/proc/sys/kernel/random/entropy_avail"
	PoolSize 	 	 = "/proc/sys/kernel/random/poolsize"
)

func AvailableEntropy() (int, error) {
	if runtime.GOOS != "linux" || !helpers.FileExists(EntropyAvail) {
		return -1, fmt.Errorf("Invalid architecture for running hwrng, found system: %s", runtime.GOOS)
	}

	cmd := exec.Command("/bin/cat", EntropyAvail)

	var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return -1, fmt.Errorf("entropy() exec failed with: %s\n", err)
	}

	content := strings.TrimSuffix(string(stdout.Bytes()), "\n")

	value, err := strconv.Atoi(content)
	if err != nil {
		return -1, fmt.Errorf("entropy() strconv failed with: %s\n", err)
	}

	return value, nil
}

func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)

	// if _, err := Reader.Read(b); err != nil {
	// 	panic(err)
	// }

	return b, nil
}

func GenerateRandomFile(size int) (string) {
	filename := fmt.Sprintf("/tmp/%s", strconv.Itoa(int(time.Now().Unix())))

	if _, err := os.Create(filename); err != nil {
		panic(err)
	}

	randomBy, _ := GenerateRandomBytes(size)

	if err := ioutil.WriteFile(filename, randomBy, 0644); err != nil {
		panic(err)
	}

	return filename
}
