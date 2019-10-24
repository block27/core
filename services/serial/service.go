package serial

import (
	"bufio"
	"fmt"

	"github.com/jacobsa/go-serial/serial"
)

func Listen() {
	options := serial.OpenOptions{
			PortName:        "/dev/cu.SLAB_USBtoUART",
			BaudRate:        9600,
			DataBits:        8,
			StopBits:        1,
			MinimumReadSize: 4,
	}

	serialPort, err := serial.Open(options)
	if err != nil {
		fmt.Printf("serial.Open: %v", err)
	}

	defer serialPort.Close()

	reader := bufio.NewReader(serialPort)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}
