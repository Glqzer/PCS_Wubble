package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func checkLetter(char rune) bool {
	return ('A' <= char && char <= 'Z') || ('a' <= char && char <= 'z')
}

func VigenereDecrypt(key string, filename string) (string, error) {

	// Open the file, check for errors, and defer closing file
	file, err := os.Open(filename)
	if err != nil {
		return "Error with file", err
	}
	defer file.Close()

	// Create Scanner Object
	scanner := bufio.NewScanner(file)
	var ciphertext strings.Builder

	// Create the plaintext version of the file
	for scanner.Scan() {
		line := scanner.Text()
		for _, char := range line {
			if checkLetter(char) {
				ciphertext.WriteRune(char)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "Scanner Error", err
	}

	var plaintext strings.Builder
	for i, char := range ciphertext.String() {
		keyCharacter := key[i%len(key)]
		shift := int(keyCharacter) - 'A'
		plaintext.WriteRune(decryptCharacter(unicode.ToUpper(char), shift))
	}

	return plaintext.String(), nil
}

// Helper function to decrypt a single character using the Vigenère cipher
func decryptCharacter(char rune, shift int) rune {
	var base = int('A')

	// Apply the Vigenère cipher decryption
	return rune((int(char)-base-shift+26)%26 + base)
}

func main() {
	result, err := VigenereDecrypt(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(result)
}