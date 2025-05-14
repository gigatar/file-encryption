package encryption

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gigatar/file-encryptor/pkg/kdf"
)

// mockPasswordInput temporarily replaces the password input function with a mock
func mockPasswordInput(t *testing.T, password string) func() {
	// Save original function
	originalGetKey := kdf.GetKey

	// Replace with mock function
	kdf.GetKey = func(salt []byte) ([]byte, error) {
		// Use a fixed password for testing
		return kdf.DeriveKey([]byte(password), salt), nil
	}

	// Return cleanup function
	return func() {
		kdf.GetKey = originalGetKey
	}
}

func TestEncryptDecryptFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "encryption-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Mock password input
	cleanup := mockPasswordInput(t, "test-password-123")
	defer cleanup()

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "empty file",
			content: "",
			wantErr: false,
		},
		{
			name:    "small text file",
			content: "Hello, World!",
			wantErr: false,
		},
		{
			name:    "larger text file",
			content: "This is a larger text file with multiple lines.\nLine 2\nLine 3\nLine 4",
			wantErr: false,
		},
		{
			name:    "binary content",
			content: string([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create input file
			inputPath := filepath.Join(tempDir, "input.txt")
			if err := os.WriteFile(inputPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create input file: %v", err)
			}

			// Create paths for encrypted and decrypted files
			encryptedPath := filepath.Join(tempDir, "encrypted.bin")
			decryptedPath := filepath.Join(tempDir, "decrypted.txt")

			// Test encryption
			if err := EncryptFile(inputPath, encryptedPath); (err != nil) != tt.wantErr {
				t.Errorf("EncryptFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Skip decryption if encryption failed
			if tt.wantErr {
				return
			}

			// Test decryption
			if err := DecryptFile(encryptedPath, decryptedPath); err != nil {
				t.Errorf("DecryptFile() error = %v", err)
				return
			}

			// Read decrypted content
			decryptedContent, err := os.ReadFile(decryptedPath)
			if err != nil {
				t.Errorf("Failed to read decrypted file: %v", err)
				return
			}

			// Compare original and decrypted content
			if string(decryptedContent) != tt.content {
				t.Errorf("Decrypted content = %v, want %v", string(decryptedContent), tt.content)
			}
		})
	}
}

func TestEncryptFileErrors(t *testing.T) {
	// Mock password input
	cleanup := mockPasswordInput(t, "test-password-123")
	defer cleanup()

	tests := []struct {
		name    string
		inFile  string
		outFile string
		wantErr bool
	}{
		{
			name:    "non-existent input file",
			inFile:  "nonexistent.txt",
			outFile: "output.bin",
			wantErr: true,
		},
		{
			name:    "invalid output directory",
			inFile:  "input.txt",
			outFile: "/nonexistent/dir/output.bin",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EncryptFile(tt.inFile, tt.outFile); (err != nil) != tt.wantErr {
				t.Errorf("EncryptFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptFileErrors(t *testing.T) {
	// Mock password input
	cleanup := mockPasswordInput(t, "test-password-123")
	defer cleanup()

	tests := []struct {
		name    string
		inFile  string
		outFile string
		wantErr bool
	}{
		{
			name:    "non-existent input file",
			inFile:  "nonexistent.bin",
			outFile: "output.txt",
			wantErr: true,
		},
		{
			name:    "invalid output directory",
			inFile:  "input.bin",
			outFile: "/nonexistent/dir/output.txt",
			wantErr: true,
		},
		{
			name:    "invalid encrypted file",
			inFile:  "invalid.bin",
			outFile: "output.txt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := DecryptFile(tt.inFile, tt.outFile); (err != nil) != tt.wantErr {
				t.Errorf("DecryptFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
