# go-secwkr (simple encryption cli with key rotation)
Do not use in production. It is only a PoC. <br />
This is a simple encryption cli. It is possible to rotate your key pair. An efficient update procedure renews the encrypted data so that this data can only be decrypted with the new key pair. The update can be done by an untrusted third party. A analogous procedure is used in [Updatable Oblivious Key Management for Storage Systems](https://eprint.iacr.org/2019/1275).

## How it works

### Key Generation
A random ristretto255 key pair `(a, A)` is generated.

### File Encryption
tbd


## Usage
```
Usage:
    secwkr keygen
	secwkr [-s KEYFILE_PATH] keyrotate
	secwkr [-f FACTOR_FILE_PATH] rekey ENCAP_FILE_PATH
	secwkr [-r RECIPIENT_FILE] encrypt INPUT_FILE OUTPUT_FILE
	secwkr [-s KEYFILE_PATH] [-e ENCAP_FILE_PATH] decrypt INPUT_FILE OUTPUT_FILE
	
Options:
	-s PATH		Path to Secret Key File. Default: secretkey
	-f PATH		Path to factor File. Default: factor
	-r PATH		Path to Recipient File. Default: recipient
	-e PATH		Path to Encapsulation File. Default: <INPUT_File>.encap
```

## Example
### Key Generation
```
go run main.go keygen
```
Generates a ristretto255 keypair and writes the secret key into the file `secretkey` and the public key into the file `publickey`.

### File Encryption
```
cp publickey recipient
go run main.go encrypt test test.enc
```
Encrypts the file `test` and writes the ciphertext to the file `test.enc`. In addition, the file `test.enc.encap` is created, which contains the ephemeral public key (encapsulation).

### Key Rotation
```
go run main.go keyrotate
```
Generates a new ristretto255 key pair and writes them into the files `secretkey` and `publickey` again. In addition, a `factor` file is created in the directory in which the `secretkey` file is located. This file is necessary for the `rekey` function.

### Rekey encrypted Files
```
go run main.go rekey test.enc.encap
```
The ephemeral public key of the encrypted file is changed so that it can be decrypted with the new secret key.  More precise:
```
factor * ephemeral PK = (newSK)^-1 (oldSK) * ephemeral PK
```

### File Decryption
```
go run main.go decrypt test.enc test.dec
```
Decrypts the file `test.enc` and writes the plaintext to `text.dec`.
