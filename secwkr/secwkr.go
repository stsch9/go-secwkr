package secwkr

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const r255label = "filekey"

func KeyGen() {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	sk := ristretto255.NewScalar().FromUniformBytes(seed)
	pk := ristretto255.NewElement().ScalarBaseMult(sk)

	err := os.WriteFile("secretkey", []byte(hex.EncodeToString(sk.Encode(nil))), 0600)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("publickey", []byte(hex.EncodeToString(pk.Encode(nil))), 0600)
	if err != nil {
		panic(err)
	}
}

func KeyRotate(keyfile string) {
	basePath := filepath.Dir(keyfile)
	// read old secret key
	data, err := os.ReadFile(keyfile)
	if err != nil {
		panic(err)
	}

	oldSk, err := hex.DecodeString(string(data))
	if err != nil {
		panic(err)
	}

	s := ristretto255.NewScalar()
	if err := s.Decode(oldSk); err != nil {
		panic(err)
	}

	// generate new secret key
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	sk := ristretto255.NewScalar().FromUniformBytes(seed)
	pk := ristretto255.NewElement().ScalarBaseMult(sk)

	// calculate factor
	factor := ristretto255.NewScalar().Invert(sk)
	factor.Multiply(s, factor)

	err = os.WriteFile(basePath+"/factor", factor.Encode(nil), 0640)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(keyfile, []byte(hex.EncodeToString(sk.Encode(nil))), 0600)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(basePath+"/publickey", []byte(hex.EncodeToString(pk.Encode(nil))), 0600)
	if err != nil {
		panic(err)
	}
}

func Rekey(factor string, source string) {
	d, err := os.ReadFile(source)
	if err != nil {
		panic(err)
	}

	encap := ristretto255.NewElement()
	if err := encap.Decode(d); err != nil {
		panic(err)
	}

	f, err := os.ReadFile(factor)
	if err != nil {
		panic(err)
	}

	fac := ristretto255.NewScalar()
	if err := fac.Decode(f); err != nil {
		panic(err)
	}

	encap.ScalarMult(fac, encap)

	err = os.WriteFile(source, encap.Encode(nil), 0777)
	if err != nil {
		panic(err)
	}
}

func Encrypt(recipientfile string, source string, output string) {
	// generate ephemeral ristretto255 key pair
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	ek := ristretto255.NewScalar().FromUniformBytes(seed)
	encap := ristretto255.NewElement().ScalarBaseMult(ek)

	// read recipient Key
	data, err := os.ReadFile(recipientfile)
	if err != nil {
		panic(err)
	}

	rK, err := hex.DecodeString(string(data))
	if err != nil {
		panic(err)
	}

	K := ristretto255.NewElement()
	if err := K.Decode(rK); err != nil {
		panic(err)
	}

	// calculate shared Key = epemeral scalar * recipient Element
	sharedKey := ristretto255.NewElement().ScalarMult(ek, K)

	plaintext, err := os.ReadFile(source)
	if err != nil {
		panic(err)
	}

	// genarate random nonce
	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, 32+chacha20poly1305.NonceSizeX, 32+chacha20poly1305.NonceSizeX+len(plaintext)+chacha20poly1305.Overhead)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	//  derive file key
	h := hkdf.New(sha256.New, sharedKey.Encode(nil), nonce[:32], []byte(r255label))

	fileKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, fileKey); err != nil {
		panic(err)
	}

	aead, err := chacha20poly1305.NewX(fileKey)
	if err != nil {
		panic(err)
	}

	// Encrypt the message and append the ciphertext to the nonce.
	err = os.WriteFile(output, aead.Seal(nonce, nonce[32:], plaintext, nil), 0777)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(output+".encap", encap.Encode(nil), 0777)
	if err != nil {
		panic(err)
	}
}

func Decrypt(secretfile string, source string, output string, encapfile string) {
	rK, err := os.ReadFile(encapfile)
	if err != nil {
		panic(err)
	}

	K := ristretto255.NewElement()
	if err := K.Decode(rK); err != nil {
		panic(err)
	}

	data, err := os.ReadFile(secretfile)
	if err != nil {
		panic(err)
	}

	sK, err := hex.DecodeString(string(data))
	if err != nil {
		panic(err)
	}

	s := ristretto255.NewScalar()
	if err := s.Decode(sK); err != nil {
		panic(err)
	}

	sharedKey := ristretto255.NewElement().ScalarMult(s, K)

	ciphertext, err := os.ReadFile(source)
	if err != nil {
		fmt.Println(err)
	}

	if len(ciphertext) < 32+chacha20poly1305.NonceSizeX {
		panic("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := ciphertext[:32+chacha20poly1305.NonceSizeX], ciphertext[32+chacha20poly1305.NonceSizeX:]

	//  derive file key
	h := hkdf.New(sha256.New, sharedKey.Encode(nil), nonce[:32], []byte(r255label))

	fileKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, fileKey); err != nil {
		panic(err)
	}

	aead, err := chacha20poly1305.NewX(fileKey)
	if err != nil {
		panic(err)
	}

	plaintext, err := aead.Open(nil, nonce[32:], ciphertext, nil)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(output, plaintext, 0777)
	if err != nil {
		panic(err)
	}
}
