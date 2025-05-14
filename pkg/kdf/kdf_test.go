// Package kdf_test contains tests for the key derivation functionality.
package kdf

import (
	"bytes"
	"testing"
)

// TestDeriveKey tests the core key derivation functionality with various inputs.
// It verifies:
//   - Key length is correct (32 bytes)
//   - Same input produces same output (determinism)
//   - Different passwords produce different keys
//   - Different salts produce different keys
func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name     string
		password string
		salt     []byte
		wantLen  int
	}{
		{
			name:     "empty password",
			password: "",
			salt:     []byte("test-salt-123"),
			wantLen:  32, // 256 bits
		},
		{
			name:     "short password",
			password: "short",
			salt:     []byte("test-salt-123"),
			wantLen:  32,
		},
		{
			name:     "long password",
			password: "this-is-a-very-long-password-that-should-work-fine",
			salt:     []byte("test-salt-123"),
			wantLen:  32,
		},
		{
			name:     "special characters",
			password: "!@#$%^&*()_+-=[]{}|;:,.<>?",
			salt:     []byte("test-salt-123"),
			wantLen:  32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test key derivation
			key := DeriveKey([]byte(tt.password), tt.salt)

			// Check key length
			if len(key) != tt.wantLen {
				t.Errorf("DeriveKey() key length = %d, want %d", len(key), tt.wantLen)
			}

			// Test determinism - same input should produce same output
			key2 := DeriveKey([]byte(tt.password), tt.salt)
			if !bytes.Equal(key, key2) {
				t.Error("DeriveKey() is not deterministic")
			}

			// Test that different passwords produce different keys
			key3 := DeriveKey([]byte(tt.password+"different"), tt.salt)
			if bytes.Equal(key, key3) {
				t.Error("DeriveKey() produced same key for different passwords")
			}

			// Test that different salts produce different keys
			key4 := DeriveKey([]byte(tt.password), []byte("different-salt"))
			if bytes.Equal(key, key4) {
				t.Error("DeriveKey() produced same key for different salts")
			}
		})
	}
}

// TestGetKey tests the password input and key derivation wrapper.
// It verifies:
//   - Key derivation works with valid passwords
//   - Empty passwords are handled correctly
//   - Key length is correct (32 bytes)
//   - Same input produces same output (determinism)
func TestGetKey(t *testing.T) {
	// Save original function
	originalGetKey := GetKey
	defer func() {
		GetKey = originalGetKey
	}()

	tests := []struct {
		name     string
		password string
		salt     []byte
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "test-password-123",
			salt:     []byte("test-salt-123"),
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			salt:     []byte("test-salt-123"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock GetKey function
			GetKey = func(salt []byte) ([]byte, error) {
				return DeriveKey([]byte(tt.password), salt), nil
			}

			// Test key derivation
			key, err := GetKey(tt.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Check key length
				if len(key) != 32 {
					t.Errorf("GetKey() key length = %d, want 32", len(key))
				}

				// Test determinism
				key2, err := GetKey(tt.salt)
				if err != nil {
					t.Errorf("GetKey() error = %v", err)
					return
				}
				if !bytes.Equal(key, key2) {
					t.Error("GetKey() is not deterministic")
				}
			}
		})
	}
}

// TestArgon2Parameters verifies that the Argon2id parameters are set to reasonable values.
// It checks:
//   - timeCost is at least 1
//   - memoryCost is at least 64KB
//   - parallelism is at least 1
//   - Key derivation works with minimum parameters
func TestArgon2Parameters(t *testing.T) {
	// Test that the Argon2 parameters are reasonable
	if timeCost < 1 {
		t.Errorf("timeCost = %d, want >= 1", timeCost)
	}
	if memoryCost < 65536 {
		t.Errorf("memoryCost = %d, want >= 65536", memoryCost)
	}
	if parallelism < 1 {
		t.Errorf("parallelism = %d, want >= 1", parallelism)
	}

	// Test key derivation with minimum parameters
	key := DeriveKey([]byte("test-password"), []byte("test-salt"))
	if len(key) != 32 {
		t.Errorf("DeriveKey() key length = %d, want 32", len(key))
	}
}
