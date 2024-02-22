package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"
)

func checkLetter(char rune) bool {
	return ('A' <= char && char <= 'Z') || ('a' <= char && char <= 'z')
}

// Function to find the Vigenere Key Length using the Index of Coincidence
func FindKeyLength(filename string) (int, error) {

	// Open the file, check for errors, and defer closing file
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// Create Scanner Object
	scanner := bufio.NewScanner(file)
	var ciphertext strings.Builder

	// Create the ciphertext version of the file in a string
	for scanner.Scan() {
		line := scanner.Text()
		for _, char := range line {
			if checkLetter(char) {
				ciphertext.WriteRune(unicode.ToUpper(char))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	// We now have a string of all caps of the ciphertext
	var text = ciphertext.String()
	result := 1
	minDiff := math.MaxFloat64

	for keyLength := 2; keyLength <= 20; keyLength++ {
		averageioc := 0.0
		for i := 0; i < keyLength; i++ {
			substring := ""
			for j := i; j < len(text); j += keyLength {
				substring += string(text[j])
			}
			averageioc += indexOfCoincidence(substring)
		}
		averageioc /= float64(keyLength)

		diff := math.Abs(averageioc - 0.065)
		if diff < minDiff {
			minDiff = diff
			result = keyLength
		} else if diff == minDiff && keyLength < result {
			result = keyLength
		}
	}

	return result, nil
}

// Helper function to calculate the index of coincidence
func indexOfCoincidence(text string) float64 {
	frequencies := make(map[rune]int)
	totalChars := 0

	for _, char := range text {
		frequencies[char]++
		totalChars++
	}

	sum := 0.0
	for _, frequency := range frequencies {
		sum += float64(frequency * (frequency - 1))
	}

	return sum / (float64(totalChars) * (float64(totalChars) - 1))
}

func main() {
	result, err := FindKeyLength(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(result)
	return
}
