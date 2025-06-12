package gosdk

import (
	"crypto/aes"
	"crypto/cipher"
)

// AesEncrypt encrypts data using AES-GCM mode
// Parameters:
//
//	data  - plaintext to be encrypted
//	key   - encryption key (must be 16, 24 or 32 bytes for AES-128/192/256)
//	nonce - nonce (must be 12 bytes)
//
// Returns:
//
//	[]byte - ciphertext with authentication tag
//	error  - encryption errors (invalid key length, etc.)
func AesEncrypt(data, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}

// AesDecrypt decrypts data using AES-GCM mode
// Parameters:
//
//	data  - ciphertext with authentication tag
//	key   - decryption key (same requirements as AesEncrypt)
//	nonce - nonce used during encryption
//
// Returns:
//
//	[]byte - decrypted plaintext
//	error  - decryption errors (authentication failure, invalid ciphertext)
func AesDecrypt(data, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
