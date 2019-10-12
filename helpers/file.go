package helpers

import (
	"bufio"
	"io/ioutil"
	"os"
)

func FileExists(name string) bool {
    if _, err := os.Stat(name); err != nil {
        if os.IsNotExist(err) {
            return false
        }
    }

    return true
}

func ReadFile(filename string) string {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
  }

	return string(b)
}

func ReadBinary(filename string) []byte {
    file, err := os.Open(filename)

    if err != nil {
        panic(err)
    }
    defer file.Close()

    stats, statsErr := file.Stat()
    if statsErr != nil {
        panic(statsErr)
    }

    var size int64 = stats.Size()
    bytes := make([]byte, size)

    bufr := bufio.NewReader(file)
    _,err = bufr.Read(bytes)
		if err != nil {
				panic(err)
		}

    return bytes
}
