// Package encryption_test contains tests for the encryption package.
// It verifies the functionality of file encryption and decryption,
// including error handling and large file support.
package encryption_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/gigatar/file-encryptor/pkg/encryption"
	"github.com/gigatar/file-encryptor/pkg/kdf"
)

// mockGetKey is a mock implementation of kdf.GetKeyFunc for testing.
// It returns a fixed key for consistent test results.
func mockGetKey(salt []byte) ([]byte, error) {
	return make([]byte, 32), nil // Return a 32-byte key (AES-256)
}

// TestEncryptDecrypt verifies that a file can be encrypted and then decrypted
// back to its original content. It tests the basic functionality of the
// encryption and decryption process.
func TestEncryptDecrypt(t *testing.T) {
	// Save original GetKey function and restore it after the test
	originalGetKey := kdf.GetKey
	kdf.GetKey = mockGetKey
	defer func() { kdf.GetKey = originalGetKey }()

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "encryption-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test file with random content
	inputPath := filepath.Join(tempDir, "input.txt")
	outputPath := filepath.Join(tempDir, "output.enc")
	decryptedPath := filepath.Join(tempDir, "decrypted.txt")

	// Generate random test data
	testData := make([]byte, 1024)
	if _, err := rand.Read(testData); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Write test data to input file
	if err := os.WriteFile(inputPath, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test encryption
	if err := encryption.EncryptFile(inputPath, outputPath); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify encrypted file exists and is different from input
	encryptedData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	if bytes.Equal(encryptedData, testData) {
		t.Fatal("Encrypted file is identical to input file")
	}

	// Test decryption
	if err := encryption.DecryptFile(outputPath, decryptedPath); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted file matches original
	decryptedData, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}
	if !bytes.Equal(decryptedData, testData) {
		t.Fatal("Decrypted file does not match original")
	}
}

// TestLargeFileEncryption verifies that the encryption and decryption
// process works correctly with large files. It tests the chunked processing
// functionality to ensure it can handle files larger than the chunk size.
func TestLargeFileEncryption(t *testing.T) {
	// Save original GetKey function and restore it after the test
	originalGetKey := kdf.GetKey
	kdf.GetKey = mockGetKey
	defer func() { kdf.GetKey = originalGetKey }()

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "encryption-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test file paths
	inputPath := filepath.Join(tempDir, "large-input.txt")
	outputPath := filepath.Join(tempDir, "large-output.enc")
	decryptedPath := filepath.Join(tempDir, "large-decrypted.txt")

	// Create a large file (2MB)
	fileSize := 2 * 1024 * 1024
	largeData := make([]byte, fileSize)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("Failed to generate large test data: %v", err)
	}

	// Write large test data to input file
	if err := os.WriteFile(inputPath, largeData, 0644); err != nil {
		t.Fatalf("Failed to write large test file: %v", err)
	}

	// Test encryption
	if err := encryption.EncryptFile(inputPath, outputPath); err != nil {
		t.Fatalf("Large file encryption failed: %v", err)
	}

	// Verify encrypted file exists and is different from input
	encryptedData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted large file: %v", err)
	}
	if bytes.Equal(encryptedData, largeData) {
		t.Fatal("Encrypted large file is identical to input file")
	}

	// Test decryption
	if err := encryption.DecryptFile(outputPath, decryptedPath); err != nil {
		t.Fatalf("Large file decryption failed: %v", err)
	}

	// Verify decrypted file matches original
	decryptedData, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted large file: %v", err)
	}
	if !bytes.Equal(decryptedData, largeData) {
		t.Fatal("Decrypted large file does not match original")
	}
}

// TestErrorHandling verifies that the encryption and decryption functions
// handle various error conditions appropriately.
func TestErrorHandling(t *testing.T) {
	// Save original GetKey function and restore it after the test
	originalGetKey := kdf.GetKey
	kdf.GetKey = mockGetKey
	defer func() { kdf.GetKey = originalGetKey }()

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "encryption-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test cases for error handling
	testCases := []struct {
		name        string
		inputPath   string
		outputPath  string
		expectError bool
	}{
		{
			name:        "Nonexistent input file",
			inputPath:   filepath.Join(tempDir, "nonexistent.txt"),
			outputPath:  filepath.Join(tempDir, "output.enc"),
			expectError: true,
		},
		{
			name:        "Invalid output directory",
			inputPath:   filepath.Join(tempDir, "input.txt"),
			outputPath:  "/nonexistent/directory/output.enc",
			expectError: true,
		},
	}

	// Create a test file for valid input tests
	validInputPath := filepath.Join(tempDir, "input.txt")
	testData := []byte("test data")
	if err := os.WriteFile(validInputPath, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test encryption
			err := encryption.EncryptFile(tc.inputPath, tc.outputPath)
			if (err != nil) != tc.expectError {
				t.Errorf("Encryption error = %v, want error = %v", err, tc.expectError)
			}

			// Test decryption
			err = encryption.DecryptFile(tc.inputPath, tc.outputPath)
			if (err != nil) != tc.expectError {
				t.Errorf("Decryption error = %v, want error = %v", err, tc.expectError)
			}
		})
	}
}
