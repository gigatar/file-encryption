package kdf

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	timeCost    = uint32(3)
	memoryCost  = uint32(65536)
	parallelism = uint32(1)
)

func GetKey(salt []byte) ([]byte, error) {
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

	key := argon2.IDKey(password, salt, timeCost, memoryCost, uint8(parallelism), 32)

	return key, nil
}
