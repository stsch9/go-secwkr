# go-secwkr (simple encryption cli with key rotation)
Do not use in production. It is only a PoC. <br />
This is a simple encryption cli. It is possible to rotate your key pair. An efficient update procedure renews the encrypted data so that this data can only be decrypted with the new key pair. The update can be done by an untrusted third party. A analogous procedure is used in [Updatable Oblivious Key Management for Storage Systems](https://eprint.iacr.org/2019/1275).

## How it works

### Key Generation
A random ristretto255 key pair `(a, A)` is generated.

### File Encryption
A ephemeral ristretto255 key pair `(e, E)` is generated for each file. The recipient's public key `B` is used to calculate a shared key, where `(b, B)` is the recipient's key pair:
```
shared_key = e * B
```
where `*` denotes the scalar multiplication over the elliptic curve ristretto255. <br />
The shared Key `shared_key` is used to calculte the `file_key`:
```
file_key = HKDF(secret=shared_key, salt=nonce, info="filekey")
```
where `nonce = Random(32)` and sha256 is used as hash function.

Finally, the file is encrypted with XChaCha20-Poly1305 and the `file_key`:
```
encrypted_file = XChaCha20-Poly1305(nonce=Random(24), plaintext=file, additionalData="")
```
The two random numbers are stored in the encrypted file.
The ephemeral public key is stored in an extra file, since it changes with key rotation. <br />
To be honest, ChaCha20-Poly1305 with a fixed nonce would probably suffice, since a random nonce has already been used to create the `file_key`(see [age Spec](https://github.com/C2SP/C2SP/blob/main/age.md)).

### File Decryption
The receiver uses the private key `b` and the ephemeral public key `E` to calculate the `shared_key`.
```
shared_key = b * E = e * B
```
With this `shared_key` and the two nonces, the recipient can decrypt the file.

### Key Rotation
Suppose the recipient wants to renew his key pair. He generates a new random ristretto255 key pair `(c, C)`. In addition, a so-called `factor` file is created, which contains the scalar product of `b` and the multiplicative inverse of `c`:
```
factor = b * c^-1 (mod L)
```
where `L` is L the order of the ristretto255 group: (2^252 + 27742317777372353535851937790883648493).

### Rekey
The ephemeral public key of all files is multiplied by the `factor` generated during key rotation:
```
F = factor * E
```
This allows the recipient to decrypt the files with his new private key `c`, since the recipient receives the same `shared_key` as the sender:
```
c * F = c * (factor * E) = c * ((b * c^-1) * E) = b * E = e * B = shared_key
```
Since neither the new private key `c` nor the old private key `b`can be calculated from the `factor`, the rekey operation can be executed by an untrusted third party.


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
