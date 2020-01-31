package main

import (
	"fmt"
	"time"

	"github.com/google/gousb"
)

const (
  product = 0x0483
	serial = 2002140
  vendor = 0x16c0
)

// MPD26 struct for holding context
type MPD26 struct {
  context *gousb.Context
  device *gousb.Device
  intf *gousb.Interface
  endpoint *gousb.InEndpoint
	faders map[int]chan int
	knobs map[int]chan int
	pads map[int]chan int
}

func main() {

}

// func getInfo1() {
// 	ctx, _ := libusb.Init()
//     defer ctx.Exit()
//     devices, _ := ctx.GetDeviceList()
//     for _, device := range devices {
//         usbDeviceDescriptor, _ := device.GetDeviceDescriptor()
//         handle, _ := device.Open()
//         defer handle.Close()
//         snIndex := usbDeviceDescriptor.SerialNumberIndex
//         serialNumber, _ := handle.GetStringDescriptorASCII(snIndex)
//         fmt.Printf("Found S/N: %s", serialNumber)
//     }
// }

func getInfo2() {
	ctx := gousb.NewContext()
	devices, _ := ctx.OpenDevices(findMPD26(product, vendor))

	fmt.Printf("Devices: %d\n", len(devices))

	for _, d := range devices {
		fmt.Println(d)
	}

	devices[0].SetAutoDetach(true)
	// for num := range devices[0].Desc.Configs {
	//   config, _ := devices[0].Config(num)
	//
	//   // In a scenario where we have an error, we can continue
	//   // to the next config. Same is true for interfaces and
	//   // endpoints.
	//   defer config.Close()
	//
	//   // Iterate through available interfaces for this configuration
	//   for _, desc := range config.Desc.Interfaces {
	//     intf, _ := config.Interface(desc.Number, 0)
	//
	//     // Iterate through endpoints available for this interface.
	//     for _, endpointDesc := range intf.Setting.Endpoints {
	//       // We only want to read, so we're looking for IN endpoints.
	//       if endpointDesc.Direction == gousb.EndpointDirectionIn {
	//         endpoint, _ := intf.InEndpoint(endpointDesc.Number)
	// 				mpd := &MPD26{
	// 				  context: ctx,
	// 				  device: devices[0],
	// 				  intf: intf,
	// 				  endpoint: endpoint,
	// 				}
	//
	// 				go mpd.read(endpointDesc.PollInterval, endpointDesc.MaxPacketSize)
	//       }
	//     }
	//   }
	// }
}

func findMPD26(product, vendor uint16) func(desc *gousb.DeviceDesc) bool {
  return func(desc *gousb.DeviceDesc) bool {
    return desc.Product == gousb.ID(product) && desc.Vendor == gousb.ID(vendor)
  }
}

func (mpd *MPD26) read(interval time.Duration, maxSize int) []byte {
  ticker := time.NewTicker(interval)
  defer ticker.Stop()

  for {
    select {
    case <-ticker.C:
      buff := make([]byte, maxSize)
      n, _ := mpd.endpoint.Read(buff)

			return buff[:n]
    }
  }
}
