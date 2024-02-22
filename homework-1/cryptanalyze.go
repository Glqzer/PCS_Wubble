package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"unicode"
)

const alphabetSize = 26

// English letter frequencies obtained from a large corpus
var expectedFreq = []float64{
	0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
	0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
	0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
	0.00978, 0.0236, 0.0015, 0.01974, 0.00074, // V-Z
}

// chiSquared computes the chi-squared statistic for the observed and expected frequency distributions.
func chiSquared(observedFreq []float64, expectedFreq []float64) float64 {
	var chiSq float64
	for i := range observedFreq {
		// Avoid division by zero and ignore characters with zero expected frequency
		if expectedFreq[i] != 0 {
			chiSq += math.Pow(observedFreq[i]-expectedFreq[i], 2) / expectedFreq[i]
		}
	}
	return chiSq
}

// shiftBy applies a shift to a byte, wrapping around the alphabet.
func shiftBy(char byte, shift int) byte {
	return byte((int(char-'A')+shift)%alphabetSize + 'A')
}

func checkLetter(char rune) bool {
	return ('A' <= char && char <= 'Z') || ('a' <= char && char <= 'z')
}

func Cryptanalyze(filename string, keyLength int) (string, error) {

	file, err := os.Open(filename)
	if err != nil {
		return "", err
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
		return "", err
	}

	// We now have a string of all caps of the ciphertext
	var text = ciphertext.String()

	// Initialize an empty key
	key := make([]byte, keyLength)

	// Iterate over each position in the key
	for i := 0; i < keyLength; i++ {
		// Extract characters at intervals of keyLength from the ciphertext
		columnChars := make([]byte, 0)
		for j := i; j < len(text); j += keyLength {
			columnChars = append(columnChars, text[j])
		}

		// Calculate observed frequency distribution
		observedFreq := make([]float64, alphabetSize)
		total := 0
		for _, char := range columnChars {
			if char >= 'A' && char <= 'Z' {
				observedFreq[char-'A']++
				total++
			}
		}
		for j := range observedFreq {
			observedFreq[j] /= float64(total)
		}

		// Try all possible shifts and select the one with the lowest chi-squared statistic
		minChiSquared := math.Inf(1)
		bestShift := 0
		for shift := 0; shift < alphabetSize; shift++ {
			shiftedFreq := make([]float64, alphabetSize)
			for j := range shiftedFreq {
				shiftedFreq[j] = observedFreq[(j+shift)%alphabetSize]
			}
			currentChiSquared := chiSquared(shiftedFreq, expectedFreq)
			if currentChiSquared < minChiSquared {
				minChiSquared = currentChiSquared
				bestShift = shift
			}
		}

		// Calculate the key character based on the best shift
		key[i] = shiftBy('A', 26-bestShift)
	}

	return string(key), nil
}


func main() {
	i, err := strconv.Atoi(os.Args[2])
	result, err := Cryptanalyze(os.Args[1], i)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(result)
}
