package helpers

import (
	"testing"
)

func TestNewFile(t *testing.T) {
	file, err := NewFile("../data/hello")
	if err != nil {
		t.Fail()
	}

	if file.GetPath() != "../data/hello" {
		t.Fail()
	}

	if file.GetMD5() != "5d41402abc4b2a76b9719d911017c592" {
		t.Fail()
	}

	if file.GetSHA256() != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
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
