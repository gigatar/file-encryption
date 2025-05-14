// Package kdf provides key derivation functionality using Argon2id.
// It implements password-based key derivation with salt and configurable parameters
// for memory hardness, CPU cost, and parallelism.
package kdf

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// Argon2id parameters for key derivation
const (
	// timeCost represents the number of iterations over memory
	timeCost = uint32(3)

	// memoryCost represents the memory usage in KiB (64 MiB)
	memoryCost = uint32(65536)

	// parallelism represents the number of threads to use
	parallelism = uint32(1)
)

// DeriveKey derives a cryptographic key from a password and salt using Argon2id.
// The function uses the following parameters:
//   - timeCost: 3 iterations
//   - memoryCost: 64 MiB
//   - parallelism: 1 thread
//   - keyLength: 32 bytes (256 bits)
//
// The function is deterministic: the same password and salt will always produce
// the same key. Different passwords or salts will produce different keys.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, timeCost, memoryCost, uint8(parallelism), 32)
}

// GetKeyFunc is the type for the key derivation function that reads a password
// from stdin and derives a key. This type is used to allow mocking in tests.
type GetKeyFunc func(salt []byte) ([]byte, error)

// DefaultGetKey reads a password from stdin and derives a key using Argon2id.
// The password is read securely without echoing to the terminal.
// The function returns a 32-byte key derived from the password and salt.
func DefaultGetKey(salt []byte) ([]byte, error) {
	var password []byte
	fmt.Print("Enter password: ")

	// Set terminal to raw so we don't echo the password
	state, err := term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}

	if password, err = term.ReadPassword(int(syscall.Stdin)); err != nil {
		return nil, err
	}

	if restoreErr := term.Restore(int(syscall.Stdin), state); restoreErr != nil {
		return nil, err
	}

	fmt.Println()

	return DeriveKey(password, salt), nil
}

// GetKey is the function used to get the encryption key.
// It can be replaced in tests to avoid actual password input.
var GetKey GetKeyFunc = DefaultGetKey
