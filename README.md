# File Encryption Tool

A simple command-line tool for encrypting and decrypting files using Go with AES-GCM-SIV encryption.

## Features

- File encryption and decryption
- Simple command-line interface
- Cross-platform support

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/gigatar/file-encryptor.git
cd file-encryptor
```

2. Build the application:
```bash
go build -o file-encryptor ./cmd/file-encryption.go
```

### Cross-Compilation

To build for different platforms, use the following commands:

```bash
# For Windows (64-bit)
GOOS=windows GOARCH=amd64 go build -o file-encryptor.exe ./cmd/file-encryption.go

# For Linux (64-bit)
GOOS=linux GOARCH=amd64 go build -o file-encryptor ./cmd/file-encryption.go

# For macOS (64-bit)
GOOS=darwin GOARCH=amd64 go build -o file-encryptor ./cmd/file-encryption.go

# For macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o file-encryptor ./cmd/file-encryption.go
```

### Minimizing Binary Size

To create a smaller binary, you can use the following build flags:

```bash
# Basic size optimization
go build -ldflags="-s -w" -o file-encryptor ./cmd/file-encryption.go

# Maximum size optimization (includes stripping debug info and symbols)
go build -ldflags="-s -w -H=windowsgui" -o file-encryptor ./cmd/file-encryption.go
```

The flags explained:
- `-s`: Removes symbol table and debug information
- `-w`: Removes DWARF symbol table
- `-H=windowsgui`: (Windows only) Removes console window

## Usage

```bash
file-encryptor [encrypt|decrypt] -in <input> -out <output>
```

### Examples

Encrypt a file:
```bash
file-encryptor encrypt -in secret.txt -out secret.txt.enc
```

Decrypt a file:
```bash
file-encryptor decrypt -in secret.txt.enc -out secret.txt
```
