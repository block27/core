package main

import (
	"bytes"
	"os"
	"os/exec"
    "fmt"
	"runtime"
	"strconv"
	"strings"
)

const (
	EntropyAvail = "/proc/sys/kernel/random/entropy_avail"
	PoolSize 	 = "/proc/sys/kernel/random/poolsize"

	MasterKey = "salktrwy5duqhbnc3zcpx6mtgyx738ec"
	Base1PIN  = "m8h8bde5hpzsvksc4aljspl5dlu2sxbv"
	Base2PIN  = "txk37aqp7l4wjj8j63t7jqm9cdxzjhcu"
	
	KeyPath   = "/var/data/key"
	Base1Path = "/var/data/pin1"
	Base2Path = "/var/data/pin2" 
)

func main() {
	fmt.Printf("Runtime: %s\n", runtime.GOOS)

	val, err := entropy()
	if err !=nil {
		fmt.Println(err)
	}
	fmt.Printf("Entropy: %d\n", val)
}

func entropy() (int, error) {
	if runtime.GOOS != "linux" || !fileExists(EntropyAvail) {
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

func fileExists(name string) bool {
    if _, err := os.Stat(name); err != nil {
        if os.IsNotExist(err) {
            return false
        }
    }

    return true
}
