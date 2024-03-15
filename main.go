package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/stsch9/secwkr/secwkr"
)

const usage = `Usage:
	secwkr keygen
	secwkr [-s KEYFILE_PATH] keyrotate
	secwkr [-f FACTOR_FILE_PATH] rekey ENCAP_FILE_PATH
	secwkr [-r RECIPIENT_FILE] encrypt INPUT_FILE OUTPUT_FILE
	secwkr [-s KEYFILE_PATH] [-e ENCAP_FILE_PATH] decrypt INPUT_FILE OUTPUT_FILE
	
Options:
	-s PATH		Path to Secret Key File. Default: secretkey
	-f PATH		Path to factor File. Default: factor
	-r PATH		Path to Recipient File. Default: recipient
	-e PATH		Path to Encapsulation File. Default: <INPUT_File>.encap`

func main() {

	keyFlag := flag.String("s", "secretkey", "secret_key file path")
	recipientFlag := flag.String("r", "recipient", "recpient file")
	factorFlag := flag.String("f", "factor", "factor file")
	encapFlag := flag.String("e", "", "encapsulation file path")
	flag.Parse()

	// If not enough args, return usage
	if len(flag.Args()) < 1 {
		fmt.Println(usage)
		os.Exit(0)
	}

	function := flag.Arg(0)

	switch function {
	case "help":
		fmt.Println(usage)
		os.Exit(0)
	case "keygen":
		keygenHandle()
	case "keyrotate":
		keyrotateHandle(*keyFlag)
	case "rekey":
		rekeyHandle(*factorFlag)
	case "encrypt":
		encryptHandle(*recipientFlag)
	case "decrypt":
		decryptHandle(*keyFlag, *encapFlag)
	default:
		fmt.Println("Run secwkr help to show usage.")
		os.Exit(1)
	}

}

func keygenHandle() {
	if len(flag.Args()) != 1 {
		fmt.Println(usage)
		os.Exit(0)
	}

	secwkr.KeyGen()
}

func keyrotateHandle(keyfile string) {
	if len(flag.Args()) != 1 {
		fmt.Println(usage)
		os.Exit(0)
	}

	if !validateFile(keyfile) {
		fmt.Println("File " + keyfile + " not found")
		os.Exit(1)
	}

	secwkr.KeyRotate(keyfile)
}

func rekeyHandle(factorfile string) {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	if !validateFile(factorfile) {
		fmt.Println("File " + factorfile + " not found")
		os.Exit(1)
	}

	encapfile := flag.Arg(1)

	if !validateFile(encapfile) {
		fmt.Println("File " + encapfile + " not found")
		os.Exit(1)
	}

	secwkr.Rekey(factorfile, encapfile)
}

func encryptHandle(recipientfile string) {

	if len(flag.Args()) != 3 {
		fmt.Println(usage)
		os.Exit(0)
	}

	if !validateFile(recipientfile) {
		fmt.Println("File " + recipientfile + " not found")
		os.Exit(1)
	}

	inputfile := flag.Arg(1)

	if !validateFile(inputfile) {
		fmt.Println("File " + inputfile + " not found")
		os.Exit(1)
	}

	secwkr.Encrypt(recipientfile, inputfile, flag.Arg(2))
	//fmt.Println("\nFile successfully protected")

}

func decryptHandle(secretfile string, encapfile string) {

	if len(flag.Args()) != 3 {
		fmt.Println(usage)
		os.Exit(0)
	}

	if !validateFile(secretfile) {
		fmt.Println("File " + secretfile + " not found")
		os.Exit(1)
	}

	inputfile := flag.Arg(1)

	if !validateFile(inputfile) {
		fmt.Println("File " + inputfile + " not found")
		os.Exit(1)
	}

	if len(encapfile) == 0 {
		encapfile = flag.Arg(1) + ".encap"
	}

	if !validateFile(encapfile) {
		fmt.Println("File " + encapfile + " not found")
		os.Exit(1)
	}

	secwkr.Decrypt(secretfile, inputfile, flag.Arg(2), encapfile)
	//fmt.Println("\nFile successfully protected")

}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}

	return true
}
