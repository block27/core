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
	b.ValidateKeys()

	// Start the CLI
	c.Execute(b)
}
