package helpers

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// File interface
type File interface {
	readBinary(string) ([]byte, error)

	GetBody() []byte
	GetPath() string

	GetMD5() string
	GetSHA1() string
	GetSHA256() string
}

type file struct {
	Body []byte
	Path string

	MD5    [16]byte
	SHA256 [32]byte
	SHA1   [20]byte
}

// NewFile returns a new object of File interface
func NewFile(path string) (File, error) {
	if !FileExists(path) {
		return nil, fmt.Errorf("%s %s", RFgB("invalid or missing file: "), path)
	}

	//  Create our new instance of file
	f := &file{
		Path: path,
	}

	data, err := f.readBinary(path)
	if err != nil {
		return nil, fmt.Errorf("%s", RFgB("error reading file"))
	}

	f.Body = data
	f.MD5 = md5.Sum(data)
	f.SHA256 = sha256.Sum256(data)
	f.SHA1 = sha1.Sum(data)

	return f, nil
}

func (f *file) GetBody() []byte {
	return f.Body
}
func (f *file) GetPath() string {
	return f.Path
}

func (f *file) GetMD5() string {
	return hex.EncodeToString(f.MD5[:])
}
func (f *file) GetSHA256() string {
	return fmt.Sprintf("%x", f.SHA256[:])
}
func (f *file) GetSHA1() string {
	return fmt.Sprintf("%x", f.SHA1[:])
}

// ReadBinary ...
func (f *file) readBinary(filename string) ([]byte, error) {
	file, err := os.Open(filename)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}

	size := stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// FileExists ...
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// MD5File ...
func MD5File(filePath string) (string, error) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	//Open the passed argument and check for any error
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	//Tell the program to call the following function when the current function returns
	defer file.Close()

	//Open a new hash interface to write to
	hash := md5.New()

	//Copy the file in the hash interface and check for any error
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]

	//Convert the bytes to a string
	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil
}

// ReadFile ...
func ReadFile(filename string) (string, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// ReadBinary ...
func ReadBinary(filename string) ([]byte, error) {
	file, err := os.Open(filename)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}

	size := stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// WriteBinary - write byte data to file
func WriteBinary(file string, data []byte) (int, error) {
	handle, err := os.OpenFile(
		file,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		return 0, err
	}

	defer handle.Close()

	bytesWritten, err := handle.Write(data)
	if err != nil {
		return 0, err
	}

	return bytesWritten, nil
}
