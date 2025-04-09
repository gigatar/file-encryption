package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"

	"github.com/gigatar/file-encryptor/pkg/kdf"
)

const (
	chunkSize = 64 * 1024 // 64KB
	saltSize  = 16
)

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return salt, nil
}

func generateSyntheticIV(key []byte, plainText []byte) ([]byte, error) {
	// Create Zero block
	zeroBlock := make([]byte, 16)

	// Encrypt Zeroblock to create initial block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockCipherText := make([]byte, 16)
	block.Encrypt(blockCipherText, zeroBlock)

	// XOR the result of encryption with the plaintext to create the IV
	syntheticIV := make([]byte, 12)
	copy(syntheticIV, blockCipherText[:12]) // Only need first 12 bytes for IV
	for i := 0; i < len(plainText) && i < len(syntheticIV); i++ {
		syntheticIV[i] ^= plainText[i]
	}

	return syntheticIV, nil
}

func EncryptFile(inName, outName string) error {
	inFile, err := os.Open(inName)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	salt, err := generateSalt()
	if err != nil {
		return err
	}

	key, err := kdf.GetKey(salt)
	if err != nil {
		return err
	}

	if _, err := outFile.Write(salt); err != nil {
		return err
	}

	firstChunk := make([]byte, chunkSize)
	n, err := inFile.Read(firstChunk)
	if err != nil && err != io.EOF {
		return err
	}
	nonce, err := generateSyntheticIV(key, firstChunk[:n])
	if err != nil {
		return err
	}

	// write nonce to output file
	if _, err := outFile.Write(nonce); err != nil {
		return err
	}

	// Encrypt and write first chunk
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ct := gcm.Seal(nil, nonce, firstChunk[:n], nil)

	// Write length
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(ct)))
	if _, err := outFile.Write(lenBuf); err != nil {
		return err
	}

	if _, err := outFile.Write(ct); err != nil {
		return err
	}

	nonceCounter := uint64(0)
	// Process rest of file
	for {
		n, err := inFile.Read(firstChunk)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		binary.BigEndian.PutUint64(nonce[4:], nonceCounter)
		nonceCounter++

		if _, err := outFile.Write(nonce); err != nil {
			return err
		}
		ct := gcm.Seal(nil, nonce, firstChunk[:n], nil)
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(ct)))
		if _, err := outFile.Write(lenBuf); err != nil {
			return err
		}

		if _, err := outFile.Write(ct); err != nil {
			return err
		}
	}

	return nil
}

func DecryptFile(inName, outName string) error {
	inFile, err := os.Open(inName)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return err
	}

	key, err := kdf.GetKey(salt)
	if err != nil {
		return err
	}

	// Create GCM Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	nonce := make([]byte, 12)
	lenBuf := make([]byte, 4)
	for {
		// Read Nonce
		if _, err := io.ReadFull(inFile, nonce); err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		if _, err := io.ReadFull(inFile, lenBuf); err != nil {
			return err
		}

		ctLen := binary.BigEndian.Uint32(lenBuf)
		ct := make([]byte, ctLen)

		if _, err := io.ReadFull(inFile, ct); err != nil {
			return err
		}

		// Decrypt
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return err
		}

		if _, err := outFile.Write(pt); err != nil {
			return err
		}
	}

	return nil
}
