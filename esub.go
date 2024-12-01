package main

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/blowfish"
	"os"
)

type esub struct {
	key     string
	subject string
}

func (e *esub) esubtest() bool {
	if len(e.subject) != 48 {
		return false
	}

	esub, err := hex.DecodeString(e.subject)
	if err != nil {
		return false
	}

	iv := esub[:8]
	textHash := md5.Sum([]byte("text"))
	keyHash := md5.Sum([]byte(e.key))

	block, err := blowfish.NewCipher(keyHash[:])
	if err != nil {
		return false
	}

	stream1 := cipher.NewOFB(block, iv)
	crypt1 := make([]byte, 8)
	stream1.XORKeyStream(crypt1, textHash[:8])

	stream2 := cipher.NewOFB(block, crypt1)
	crypt2 := make([]byte, 8)
	stream2.XORKeyStream(crypt2, textHash[8:16])

	result := make([]byte, 0, 24)
	result = append(result, iv...)
	result = append(result, crypt1...)
	result = append(result, crypt2...)

	newesub := hex.EncodeToString(result)
	return newesub == e.subject
}

func (e *esub) esubgen() string {
	iv := make([]byte, 8)
	_, err := rand.Read(iv)
	if err != nil {
		panic(err)
	}

	textHash := md5.Sum([]byte("text"))
	keyHash := md5.Sum([]byte(e.key))

	block, err := blowfish.NewCipher(keyHash[:])
	if err != nil {
		panic(err)
	}

	stream1 := cipher.NewOFB(block, iv)
	crypt1 := make([]byte, 8)
	stream1.XORKeyStream(crypt1, textHash[:8])

	stream2 := cipher.NewOFB(block, crypt1)
	crypt2 := make([]byte, 8)
	stream2.XORKeyStream(crypt2, textHash[8:16])

	result := make([]byte, 0, 24)
	result = append(result, iv...)
	result = append(result, crypt1...)
	result = append(result, crypt2...)

	return hex.EncodeToString(result)
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
