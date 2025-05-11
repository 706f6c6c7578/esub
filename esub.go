package main

import (
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"os"
)

type esub struct {
	key     string
	subject string
}

func (e *esub) deriveKey() []byte {
	// Argon2id parameters (adjust time/memory/threads as needed)
	salt := []byte("fixed-salt-1234") // Use a unique, constant salt (or randomize & store it)
	key := argon2.IDKey(
		[]byte(e.key),
		salt,
		3,      // iterations
		64*1024, // 64MB memory
		4,      // threads
		32,     // output key length (32 bytes for ChaCha20)
	)
	return key
}

func (e *esub) esubtest() bool {
	if len(e.subject) != 48 { // 48 hex chars = 24 bytes
		return false
	}

	esubBytes, err := hex.DecodeString(e.subject)
	if err != nil || len(esubBytes) != 24 {
		return false
	}

	nonce := esubBytes[:12]
	receivedCiphertext := esubBytes[12:]

	key := e.deriveKey()
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return false
	}

	// Hash "text" with SHA-256 (better than RIPEMD-160)
	textHash := sha3.Sum256([]byte("text"))
	expectedCiphertext := make([]byte, 12)
	cipher.XORKeyStream(expectedCiphertext, textHash[:12])

	return hex.EncodeToString(expectedCiphertext) == hex.EncodeToString(receivedCiphertext)
}

func (e *esub) esubgen() string {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	key := e.deriveKey()
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	textHash := sha3.Sum256([]byte("text"))
	ciphertext := make([]byte, 12)
	cipher.XORKeyStream(ciphertext, textHash[:12])

	return hex.EncodeToString(append(nonce, ciphertext...))
}

func main() {
	flag.Parse()
	cmdargs := flag.Args()
	switch len(cmdargs) {
	case 1:
		e := new(esub)
		e.key = cmdargs[0]
		fmt.Println(e.esubgen())
	case 2:
		e := new(esub)
		e.key = cmdargs[0]
		e.subject = cmdargs[1]
		if !e.esubtest() {
			fmt.Println("Fail: esub not generated with this key")
			os.Exit(1)
		}
		fmt.Println("Validated: esub is valid for this key")
	default:
		fmt.Println("Usage: esub <key> [subject]")
		os.Exit(2)
	}
}