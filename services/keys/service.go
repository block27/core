package keys

import (
	"crypto/ecdsa"
)

type Keys struct {
	Name 							string `mapstructure:"name"`
	Identifier 				string `mapstructure:"identifier"`

	PublicKeyPath 		string `mapstructure:"publicKeyPath"`
	PrivateKeyPath 		string `mapstructure:"privateKeyPath"`

	PublicKeyBytes 		string
	PublicKeyECDSA 		*ecdsa.PublicKey
	PrivateKeyBytes 	string
	PrivateKeyECDSA 	*ecdsa.PrivateKey
}
