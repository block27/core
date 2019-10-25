package serial

import (
	"errors"
	"fmt"

	"github.com/tarm/serial"
	// "github.com/jacobsa/go-serial/serial"
)

type SerialAPI interface {
	Request(params Request) ([]byte, error)
}

type Request struct {
	Method string
	Size int
}

type serialAPI struct {
	Config *serial.Config
}

func NewSerial(name string, baud int) SerialAPI {
	return &serialAPI{
		Config: &serial.Config{
			Name: name,
			Baud: baud,
		},
	}
}

func (e *serialAPI) Request(params Request) ([]byte, error) {
	s, err := serial.OpenPort(e.Config)
  if err != nil {
  	return nil, err
  }

	bd := fmt.Sprintf("%s\r", params.Method)
	rq, err := s.Write([]byte(bd))
	if err != nil {
		s.Close()
		return nil, err
	}

	buff := make([]byte, params.Size)
	rq, err = s.Read(buff)
	if err != nil {
		s.Close()
		return nil, err
	}

	dS := string(buff[:rq])
	dZ := len(dS)

	if dZ != params.Size {
		s.Close()
		return nil, errors.New("Key size did not match, cannot read serial values")
	}

	s.Close()

	return buff[:rq], nil
}




// func Listen() {
// 	options := serial.OpenOptions{
// 			PortName:        "/dev/cu.SLAB_USBtoUART",
// 			BaudRate:        9600,
// 			DataBits:        8,
// 			StopBits:        1,
// 			MinimumReadSize: 4,
// 	}
//
// 	serialPort, err := serial.Open(options)
// 	if err != nil {
// 		fmt.Printf("serial.Open: %v", err)
// 	}
//
// 	defer serialPort.Close()
//
// 	reader := bufio.NewReader(serialPort)
// 	scanner := bufio.NewScanner(reader)
//
// 	for scanner.Scan() {
// 		fmt.Println(scanner.Text())
// 	}
// }
