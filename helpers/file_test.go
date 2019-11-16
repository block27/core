package helpers

import (
	"testing"
)

func TestNewFile(t *testing.T) {
	file, err := NewFile("../data/hello.txt")
	if err != nil {
		t.Fail()
	}

	if file.GetPath() != "../data/hello.txt" {
		t.Fail()
	}


	if string(file.GetBody()) == "hello" {
		t.Fail()
	}

	if file.GetMD5() != "b1946ac92492d2347c6235b4d2611184" {
		t.Fail()
	}

	if file.GetSHA() != "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" {
		t.Fail()
	}
}

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

	if err != nil {
		t.Fail()
	}
}

func TestReadFileNot(t *testing.T) {
	_, err := ReadFile("main.go")

	if err == nil {
		t.Fail()
	}
}
