package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// Helper function to check if a character is alphabetic
func checkLetter(char rune) bool {
	return ('A' <= char && char <= 'Z') || ('a' <= char && char <= 'z')
}

// Helper function to encrypt a single character using the Vigenère cipher
func encryptCharacter(char rune, shift int) rune {
	var base = int('A')
	// Apply the Vigenère cipher encryption
	return rune((int(char)-base+shift)%26 + base)
}

func VigenereEncrypt(key string, filename string) (string, error) {

	// Open the file, check for errors, and defer closing file
	file, err := os.Open(filename)
	if err != nil {
		return "Error with file", err
	}
	defer file.Close()

	// Create Scanner Object
	scanner := bufio.NewScanner(file)
	var plaintext strings.Builder

	// Create the plaintext version of the file
	for scanner.Scan() {
		line := scanner.Text()
		for _, char := range line {
			if checkLetter(char) {
				plaintext.WriteRune(char)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "Scanner Error", err
	}

	// Create the ciphertext
	var encryptedText strings.Builder
	for i, char := range plaintext.String() {
		keyCharacter := key[i%len(key)]
		shift := int(keyCharacter) - 'A'
		encryptedText.WriteRune(encryptCharacter(unicode.ToUpper(char), shift))
	}

	return encryptedText.String(), nil
}

func main() {

	result, err := VigenereEncrypt(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(result)

}

