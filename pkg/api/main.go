package main

import (
	"encoding/json"
	"log"
	"net/http"

	// jwt "github.com/dgrijalva/jwt-go"
	"github.com/block27/core-zero/backend"
	"github.com/block27/core-zero/services/dsa/ecdsa"
)

var (
	// B - main backend interface that holds all functionality
	B *backend.Backend
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func hardwareAuthentication() error {
	// Get and check credentials, speed is subjective to the serial comm
	return B.HardwareAuthenticate()
}

func dsaList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	keys, err := ecdsa.ListECDSA(*B.C)
	if err != nil {
		panic(err)
	}

	if len(keys) == 0 {
		w.Write(nil)
	}

	jData, err := json.Marshal(keys)
	if err != nil {
		panic(err)
	}

	w.Write(jData)
}

func main() {
	var e error

	// Initalize a new client, the base entrpy point to the application code
	B, e = backend.NewBackend()
	if e != nil {
		panic(e)
	}

	// Defer the database connection
	defer B.D.Close()

	// AES HW authentication
	if err := hardwareAuthentication(); err != nil {
		panic(err)
	}

	http.HandleFunc("/api/v1/dsa/list", dsaList)

	B.L.Println("Listening 0.0.0.0:7777")
	fatal(http.ListenAndServe(":7777", nil))
}
