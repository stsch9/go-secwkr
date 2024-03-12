package simplecrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const r255label = "filekey"

func main() {
	KeyGen()
	Encrypt("test", "publickey")
	KeyRotate()
	Rekey("test", "factor")
	Decrypt("test", "secretkey")
}

func KeyGen() {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	sk := ristretto255.NewScalar().FromUniformBytes(seed)
	pk := ristretto255.NewElement().ScalarBaseMult(sk)

	err := os.WriteFile("secretkey", []byte(hex.EncodeToString(sk.Encode(nil))), 0600)
	if err != nil {
		// print it out
		fmt.Println(err)
	}

	err = os.WriteFile("publickey", []byte(hex.EncodeToString(pk.Encode(nil))), 0600)
	if err != nil {
		// print it out
		fmt.Println(err)
	}
}

func KeyRotate() {
	// read old secret key
	data, err := os.ReadFile("secretkey")
	// if our program was unable to read the file
	// print out the reason why it can't
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

	err = os.WriteFile("factor", factor.Encode(nil), 0640)
	if err != nil {
		// print it out
		fmt.Println(err)
	}

	err = os.WriteFile("secretkey", []byte(hex.EncodeToString(sk.Encode(nil))), 0600)
	if err != nil {
		// print it out
		fmt.Println(err)
	}

	err = os.WriteFile("publickey", []byte(hex.EncodeToString(pk.Encode(nil))), 0600)
	if err != nil {
		// print it out
		fmt.Println(err)
	}
}

func Rekey(source string, factor string) {
	d, err := os.ReadFile(source + ".encap")
	// if our program was unable to read the file
	// print out the reason why it can't
	if err != nil {
		panic(err)
	}

	encap := ristretto255.NewElement()
	if err := encap.Decode(d); err != nil {
		panic(err)
	}

	f, err := os.ReadFile(factor)
	// if our program was unable to read the file
	// print out the reason why it can't
	if err != nil {
		panic(err)
	}

	fac := ristretto255.NewScalar()
	if err := fac.Decode(f); err != nil {
		panic(err)
	}

	encap.ScalarMult(fac, encap)

	err = os.WriteFile(source+".encap", encap.Encode(nil), 0777)
	if err != nil {
		// print it out
		fmt.Println(err)
	}
}

func Encrypt(source string, recipientfile string) {
	// generate ephemeral ristretto255 key pair
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	ek := ristretto255.NewScalar().FromUniformBytes(seed)
	encap := ristretto255.NewElement().ScalarBaseMult(ek)

	// read recipient Key
	data, err := os.ReadFile(recipientfile)
	// if our program was unable to read the file
	// print out the reason why it can't
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
	// if our program was unable to read the file
	// print out the reason why it can't
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
	err = os.WriteFile(source+".enc", aead.Seal(nonce, nonce[32:], plaintext, nil), 0777)
	// handle this error
	if err != nil {
		// print it out
		fmt.Println(err)
	}

	err = os.WriteFile(source+".encap", encap.Encode(nil), 0777)
	if err != nil {
		// print it out
		fmt.Println(err)
	}
}

func Decrypt(source string, secretfile string) {
	rK, err := os.ReadFile(source + ".encap")
	// if our program was unable to read the file
	// print out the reason why it can't
	if err != nil {
		panic(err)
	}

	K := ristretto255.NewElement()
	if err := K.Decode(rK); err != nil {
		panic(err)
	}

	data, err := os.ReadFile(secretfile)
	// if our program was unable to read the file
	// print out the reason why it can't
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

	ciphertext, err := os.ReadFile(source + ".enc")
	// if our program was unable to read the file
	// print out the reason why it can't
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

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce[32:], ciphertext, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", plaintext)
}
