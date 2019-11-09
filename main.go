package main

import (
	"github.com/amanelis/bespin/backend"
	c "github.com/amanelis/bespin/cmd"
)

func main() {
	// Initalize a new client, the base entrpy point to the application code
	b, _ := backend.NewBackend()

	// Defer the database connection
	defer b.D.Close()

	// Get and check credentials, speed is subjective to the serial comm
	if err := b.ValidateKeys(); err !=nil {
		panic(err)
	}

	// Start the CLI / error if fails
	if err := c.Execute(b); err !=nil {
		panic(err)
	}
}
