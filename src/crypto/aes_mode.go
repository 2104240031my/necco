package crypto

import (
	"errors"
)

func (aes *AES) ECBEncrypt(plaintext []uint8, ciphertext []uint8) error {

	if len(plaintext) > len(ciphertext) || len(plaintext)&0x0f != 0 {
		return errors.New("")
	}

	n := len(plaintext)
	for i := 0; i < n; i = i + 16 {
		aes.Cipher(plaintext[i:i+16], ciphertext[i:i+16])
	}

	return nil

}

func (aes *AES) ECBDecrypt(plaintext []uint8, ciphertext []uint8) error {

	if len(plaintext) > len(ciphertext) || len(plaintext)&0x0f != 0 {
		return errors.New("")
	}

	n := len(plaintext)
	for i := 0; i < n; i = i + 16 {
		aes.InvCipher(plaintext[i:i+16], ciphertext[i:i+16])
	}

	return nil

}
