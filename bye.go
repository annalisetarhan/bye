package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"strings"
)

func main() {

	// Validate command line arguments
	if len(os.Args) != 3 {
		complainAboutArgs()
	}

	// Make sure file exists
	filename := os.Args[2]
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		fmt.Println("File does not exist")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		encrypt(filename)
	case "decrypt":
		decrypt(filename)
	default:
		complainAboutArgs()
	}
}

func encrypt(filename string) {
	reader := bufio.NewReader(os.Stdin)

	// Prompt user for key
	fmt.Print("Key?     ")
	key, err := reader.ReadString('\n')
	check(err)

	// Prompt user for key hint
	fmt.Print("Hint?    ")
	hint, err := reader.ReadString('\n')
	check(err)

	// Read file
	plaintext, err := os.ReadFile(filename)
	check(err)

	// Process key - single hash to encrypt, double hash to store
	salt1 := make([]byte, 8)
	salt2 := make([]byte, 8)
	_, err = io.ReadFull(rand.Reader, salt1)
	check(err)
	_, err = io.ReadFull(rand.Reader, salt2)
	check(err)

	hashFunc := sha256.New
	encryptKey := pbkdf2.Key([]byte(key), salt1, 4096, 32, hashFunc)
	storeHash := pbkdf2.Key(encryptKey, salt2, 4096, 32, hashFunc)

	// Create new AES cipher
	aescipher, err := aes.NewCipher(encryptKey)
	check(err)

	// Create new GCM cipher
	gcm, err := cipher.NewGCM(aescipher)
	check(err)

	// Create new nonce and populate it
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	check(err)

	// Encrypt and authenticate file contents
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Create file for encrypted data
	ciphertextFilename := filename + ".bye"
	err = os.WriteFile(ciphertextFilename, ciphertext, 0666) // anyone can rw, no x
	check(err)

	// Create file for metadata
	metadataFilename := "." + filename + ".bye"
	var metadata []byte
	metadata = append(metadata, storeHash...)
	metadata = append(metadata, '\n')
	metadata = append(metadata, salt1...)
	metadata = append(metadata, '\n')
	metadata = append(metadata, salt2...)
	metadata = append(metadata, '\n')
	metadata = append(metadata, nonce...)
	metadata = append(metadata, '\n')
	metadata = append(metadata, hint...)
	metadata = append(metadata, '\n')

	err = os.WriteFile(metadataFilename, metadata, 0666)
	check(err)

	// Delete old file
	err = os.Remove(filename)
	check(err)

	fmt.Printf("File successfully encrypted: %v\n", ciphertextFilename)
}

func decrypt(filename string) {
	// Retrieve encrypted file's metadata
	metadataFilename := "." + filename
	metadata, err := os.Open(metadataFilename)
	check(err)
	defer metadata.Close()

	scanner := bufio.NewScanner(metadata)
	scanner.Scan()
	storedHash := []byte(scanner.Text())
	scanner.Scan()
	salt1 := []byte(scanner.Text())
	scanner.Scan()
	salt2 := []byte(scanner.Text())
	scanner.Scan()
	nonce := []byte(scanner.Text())
	scanner.Scan()
	hint := scanner.Text()

	// Prompt user for key
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Key?     ")
	key, err := reader.ReadString('\n')
	check(err)

	// Verify key
	hashFunc := sha256.New
	encryptKey := pbkdf2.Key([]byte(key), []byte(salt1), 4096, 32, hashFunc)
	storeHash := pbkdf2.Key(encryptKey, salt2, 4096, 32, hashFunc)

	// Handle incorrect key input
	for !bytes.Equal(storeHash, storedHash) {
		fmt.Printf("Incorrect key. Hint: %v\n", hint)
		fmt.Print("Key?     ")
		key, err := reader.ReadString('\n')
		check(err)

		encryptKey = pbkdf2.Key([]byte(key), salt1, 4096, 32, hashFunc)
		storeHash = pbkdf2.Key(encryptKey, salt2, 4096, 32, hashFunc)
	}

	// Create new AES cipher
	aescipher, err := aes.NewCipher(encryptKey)
	check(err)

	// Create new GCM cipher
	gcm, err := cipher.NewGCM(aescipher)
	check(err)

	// Load encrypted file
	ciphertext, err := os.ReadFile(filename)
	check(err)

	// Decrypt file
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	check(err)

	// Create new plaintext file
	plaintextFilename := strings.TrimSuffix(filename, ".bye")
	err = os.WriteFile(plaintextFilename, plaintext, 0666)
	check(err)

	// Delete ciphertext file, metadata file
	err = os.Remove(metadataFilename)
	check(err)

	err = os.Remove(filename)
	check(err)

	fmt.Printf("File successfully decrypted: %v\n", plaintextFilename)
}

func complainAboutArgs() {
	fmt.Println("Usage: bye encrypt filename.txt")
	fmt.Println("Usage: bye decrypt filename.txt.bye")
	os.Exit(1)
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

