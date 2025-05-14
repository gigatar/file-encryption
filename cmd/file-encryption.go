// Package main implements a command-line tool for file encryption and decryption.
// It provides a simple interface to encrypt and decrypt files using AES-GCM-SIV
// encryption with password-based key derivation.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gigatar/file-encryptor/pkg/encryption"
)

// logFatal prints an error message and exits with status code 1.
func logFatal(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

// main is the entry point for the file encryption tool.
// It parses command-line arguments and performs the requested operation:
//   - encrypt: Encrypts a file using AES-GCM-SIV
//   - decrypt: Decrypts a previously encrypted file
//
// Usage:
//
//	file-encryptor [encrypt|decrypt] -in <input> -out <output>
//
// Flags:
//
//	-in:  Path to the input file
//	-out: Path to the output file
func main() {
	// Check for at least one positional argument
	if len(os.Args) < 4 {
		logFatal(fmt.Sprintf("Usage: %s [encrypt|decrypt] -in <input> -out <output>", os.Args[0]))
	}

	// First arg is the mode
	mode := os.Args[1]

	// Define flags *after* the mode argument
	fs := flag.NewFlagSet("file-encryptor", flag.ExitOnError)
	inFile := fs.String("in", "", "Input file path")
	outFile := fs.String("out", "", "Output file path")

	// Parse remaining args after mode
	if err := fs.Parse(os.Args[2:]); err != nil {
		logFatal(fmt.Sprintf("Error parsing flags: %v", err))
	}

	// Validate flags
	if *inFile == "" || *outFile == "" {
		logFatal("Both -in and -out must be specified")
	}

	// Handle mode
	switch mode {
	case "encrypt":
		if err := encryption.EncryptFile(*inFile, *outFile); err != nil {
			logFatal(fmt.Sprintf("Encryption failed: %v", err))
		}
		fmt.Println("✅ Encrypted successfully.")
	case "decrypt":
		if err := encryption.DecryptFile(*inFile, *outFile); err != nil {
			logFatal(fmt.Sprintf("Decryption failed: %v", err))
		}
		fmt.Println("✅ Decrypted successfully.")
	default:
		logFatal(fmt.Sprintf("Unknown mode: %s (must be 'encrypt' or 'decrypt')", mode))
	}
}
