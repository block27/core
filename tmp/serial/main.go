package main

import (
    "fmt"
    "github.com/google/gousb"
)

const (
  product = 0x0483
  serial = 2002140
  vendor = 0x16c0
)

// https://github.com/google/gousb/blob/master/example_test.go
// ctx := gousb.NewContext()
// defer ctx.Close()
//
// dev, err := ctx.OpenDeviceWithVIDPID(gousb.ID(d.Product), gousb.ID(d.Vendor))
// if err != nil {
//   return "", fmt.Errorf(h.RFgB("invalid authentication device"))
// }
//
// defer dev.Close()

func main() {
  ctx := gousb.NewContext()
  devices, _ := ctx.OpenDevices(findMPD26(product, vendor))

  fmt.Println(devices[0])
  fmt.Println(devices[0].Manufacturer())
  fmt.Println(devices[0].SerialNumber())
}

func findMPD26(product, vendor uint16) func(desc *gousb.DeviceDesc) bool {
  return func(desc *gousb.DeviceDesc) bool {

    if desc.Product == gousb.ID(product) && desc.Vendor == gousb.ID(vendor) {
      fmt.Printf("Product: %s\n", gousb.ID(product))
      fmt.Printf("Vendor: %s\n", gousb.ID(vendor))
      fmt.Printf("Address: %d\n", desc.Address)
      fmt.Printf("Port: %d\n", desc.Port)

      fmt.Println()
    }

    return desc.Product == gousb.ID(product) && desc.Vendor == gousb.ID(vendor)
  }
}


// Product ID: 0x0483
// Vendor ID: 0x16c0
// Version: 2.75
// Serial Number: 2002140
// Speed: Up to 12 Mb/sec
// Manufacturer: Teensyduino
// Location ID: 0x14530000 / 18
// Current Available (mA): 500
// Current Required (mA): 100
// Extra Operating Current (mA): 0
