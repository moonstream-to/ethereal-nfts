package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/term"
)

// SigningKeyFromEnv loads the relayer's Ethereum account signing key from the environment variables following this strategy:
//   - If RELAYERS_PRIVATE_KEY is set, it takes priority. This environment variable is expected to represent
//     an Ethereum account private key, and is decoded directly to the go struct that will be used for signatures.
//   - If RELAYERS_KEYSTORE is set, then it is expected to be a path to a keystore file. If RELAYERS_KEYSTORE_PASSWORD
//     is also set, that is used as the password to decrypt the keystore. Otherwise, the user is prompted for
//     this password. The signing key is the private key decrypted from this file.
func SigningKeyFromEnv() (*ecdsa.PrivateKey, error) {
	privateKeyHex := os.Getenv("RELAYERS_PRIVATE_KEY")
	if privateKeyHex != "" {
		return PrivateKey(privateKeyHex)
	}

	keystoreFile := os.Getenv("RELAYERS_KEYSTORE")
	if keystoreFile == "" {
		return nil, errors.New("RELAYERS_KEYSTORE environment variable must be set")
	}

	prompt := false
	keystorePassword, ok := os.LookupEnv("RELAYERS_KEYSTORE_PASSWORD")
	if !ok {
		prompt = true
	}
	return PrivateKeyFromKeystoreFile(keystoreFile, keystorePassword, prompt)
}

// PrivateKey decodes a private key from its hex representation.
func PrivateKey(privateKeyHex string) (*ecdsa.PrivateKey, error) {
	parsedPrivateKey, parseErr := crypto.HexToECDSA(privateKeyHex)
	return parsedPrivateKey, parseErr
}

// PrivateKeyFromKeystoreFile loads a private key from a keystore file. If prompt is true, the user will be
// interactively prompted for the password to the keystore file even if the password variable is nonempty.
func PrivateKeyFromKeystoreFile(keystoreFile, password string, prompt bool) (*ecdsa.PrivateKey, error) {
	keystoreContent, readErr := os.ReadFile(keystoreFile)
	if readErr != nil {
		return nil, readErr
	}

	// If password is "", prompt user for password.
	if prompt {
		fmt.Printf("Please provide a password for keystore (%s): ", keystoreFile)
		passwordRaw, inputErr := term.ReadPassword(int(os.Stdin.Fd()))
		if inputErr != nil {
			return nil, fmt.Errorf("error reading password: %s", inputErr.Error())
		}
		fmt.Print("\n")
		password = string(passwordRaw)
	}

	key, err := keystore.DecryptKey(keystoreContent, password)
	return key.PrivateKey, err
}

// Signs bytes using a private key and return the signature.
// The "sensible" parameter refers to the v-byte of the signature. If it is true, then the v-byte will
// be 0 or 1. Default should be sensible=false. For more information look at comment in the function implementation.
func SignRawMessage(message []byte, key *ecdsa.PrivateKey, sensible bool) ([]byte, error) {
	signature, err := crypto.Sign(message, key)
	if !sensible {
		// This refers to a bug in an early Ethereum client implementation where the v parameter byte was
		// shifted by 27: https://github.com/ethereum/go-ethereum/issues/2053
		// Default for callers should be NOT sensible.
		// Defensively, we only shift if the 65th byte is 0 or 1.
		if signature[64] < 2 {
			signature[64] += 27
		}
	}
	return signature, err
}
