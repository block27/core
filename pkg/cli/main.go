package main

import (
	"github.com/amanelis/core-zero/backend"
	c "github.com/amanelis/core-zero/cmd"
	m "github.com/awnumar/memguard"
)

func main() {
	// Memguard enclave
	m.CatchInterrupt()

	// Initalize a new client, the base entrpy point to the application code
	b, _ := backend.NewBackend()

	// Defer the database connection
	defer b.D.Close()

	// Get and check credentials, speed is subjective to the serial comm
	if err := b.HardwareAuthenticate(); err != nil {
		panic(err)
	}

	// Start the CLI / error if fails
	c.Execute(b)
}
