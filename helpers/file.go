package helpers

import (
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

func ReadContents(filename string) string {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
  }

	return string(b)
}
