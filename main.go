package main

import (
	"github.com/stsch9/simple-encrypt/simplecrypt"
)

func main() {
	simplecrypt.KeyGen()
	simplecrypt.Encrypt("test", "publickey")
	simplecrypt.KeyRotate()
	simplecrypt.Rekey("test", "factor")
	simplecrypt.Decrypt("test", "secretkey")
}
