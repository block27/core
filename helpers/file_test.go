package helpers

import (
	"testing"
)

func TestFileExists(t *testing.T) {
	if !FileExists("file.go") {
		t.Fail()
	}
}

func TestFileExistsNot(t *testing.T) {
	if FileExists("main.go") {
		t.Fail()
	}
}

func TestReadFile(t *testing.T) {
	res, err := ReadFile("file.go")

	if res == "" {
		t.Fail()
	}

	if err !=nil {
		t.Fail()
	}
}

func TestReadFileNot(t *testing.T) {
	_, err := ReadFile("main.go")

	if err == nil {
		t.Fail()
	}
}
