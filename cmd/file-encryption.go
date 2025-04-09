package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gigatar/file-encryptor/pkg/encryption"
)

func logFatal(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

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
