package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"
	//"io/ioutil"
	//"log"
)

// Globals

var (
	serverPort          int
	serverDomain        string
	serverDomainAndPort string
	serverProtocol      string
	noTLS               bool
	strictTLS           bool
	username            string
	password            string
	apiKey              string
	doUserRegister      bool
	headlessMode        bool
	messageIDCounter    int
	attachmentsDir      string
	attackFile          string
	victimUsername      string
	globalPubKey        PubKeyStruct
	globalPrivKey       PrivKeyStruct
)

type PubKeyStruct struct {
	EncPK string `json:"encPK"`
	SigPK string `json:"sigPK"`
}

type PrivKeyStruct struct {
	EncSK string `json:"encSK"`
	SigSK string `json:"sigSK"`
}

type FilePathStruct struct {
	Path string `json:"path"`
}

type APIKeyStruct struct {
	APIkey string `json:"APIkey"`
}

type MessageStruct struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Id        int    `json:"id"`
	ReceiptID int    `json:"receiptID"`
	Payload   string `json:"payload"`
	decrypted string
	url       string
	localPath string
}

type UserStruct struct {
	Username     string `json:"username"`
	CreationTime int    `json:"creationTime"`
	CheckedTime  int    `json:"lastCheckedTime"`
}

type CiphertextStruct struct {
	C1  string `json:"C1"`
	C2  string `json:"C2"`
	Sig string `json:"Sig"`
}

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Do a POST request and return the result
func doPostRequest(postURL string, postContents []byte) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postContents))
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the POST request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Do a GET request and return the result
func doGetRequest(getURL string) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the GET request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Upload a file to the server
func uploadFileToServer(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadFile/" +
		username + "/" + apiKey

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("filefield", filename)
	io.Copy(part, file)
	writer.Close()

	r, _ := http.NewRequest("POST", posturl, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	defer resp.Body.Close()

	// Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Handle error
		fmt.Println("Error while reading the response bytes:", err)
		return "", err
	}

	// Unmarshal the JSON into a map or a struct
	var resultStruct FilePathStruct
	err = json.Unmarshal(respBody, &resultStruct)
	if err != nil {
		// Handle error
		fmt.Println("Error while parsing JSON:", err)
		return "", err
	}

	// Construct a URL
	fileURL := serverProtocol + "://" + serverDomainAndPort + "/downloadFile" +
		resultStruct.Path

	return fileURL, nil
}

// Download a file from the server and return its local path
func downloadFileFromServer(geturl string, localPath string) error {
	// Get the file data
	resp, err := http.Get(geturl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// no errors; return
	if resp.StatusCode != 200 {
		return errors.New("Bad result code")
	}

	// Create the file
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Log in to server
func serverLogin(username string, password string) (string, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/login/" +
		username + "/" + password

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", errors.New("Bad result code")
	}

	// Parse JSON into an APIKey struct
	var result APIKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.APIkey, nil
}

// Log in to server
func getPublicKeyFromServer(forUser string) (*PubKeyStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + forUser

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an PubKeyStruct
	var result PubKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return &result, nil
}

// Register username with the server
func registerUserWithServer(username string, password string) error {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/registerUser/" +
		username + "/" + password

	code, _, err := doGetRequest(geturl)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Get messages from the server
func getMessagesFromServer() ([]MessageStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// TODO: Implement decryption
	decryptMessages(result)

	return result, nil
}

// Get messages from the server
func getUserListFromServer() ([]UserStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/listUsers"

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []UserStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// Sort the user list by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].CheckedTime > result[j].CheckedTime
	})

	return result, nil
}

func sendAttachmentToServer(sender string, recipient string, message []byte, readReceiptID int, url string, localPath string) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", url, localPath}
	messageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Post a message to the server
func sendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", "", ""}
	messageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Read in a message from the command line and then send it to the serve
func doReadAndSendMessage(recipient string, messageBody string) error {
	keepReading := true
	reader := bufio.NewReader(os.Stdin)

	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// If there is no message given, we read one in from the user
	if messageBody == "" {
		// Next, read in a multi-line message, ending when we get an empty line (\n)
		fmt.Println("Enter message contents below. Finish the message with a period.")

		for keepReading == true {
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}

			if strings.TrimSpace(input) == "." {
				keepReading = false
			} else {
				messageBody = messageBody + input
			}
		}
	}

	// Now encrypt the message
	encryptedMessage := encryptMessage([]byte(messageBody), username, pubkey)

	// Finally, send the encrypted message to the server
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

// Request a key from the server
func getKeyFromServer(user_key string) {
	geturl := serverProtocol + "://" + serverDomain + ":" + strconv.Itoa(serverPort) + "/lookupKey?" + user_key

	fmt.Println(geturl)
}

// Upload a new public key to the server
func registerPublicKeyWithServer(username string, pubKeyEncoded PubKeyStruct) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadKey/" +
		username + "/" + apiKey

	body, err := json.Marshal(pubKeyEncoded)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

//******************************
// Cryptography functions
//******************************

// Encrypts a file on disk into a new ciphertext file on disk, returns the HEX encoded key
// and file hash, or an error.
func encryptAttachment(plaintextFilePath string, ciphertextFilePath string) (string, string, error) {
	// TODO: IMPLEMENT

	// Select random 256-bit ChaCha20 Key
	key := make([]byte, 32)
	_, error := rand.Read(key)

	// Error handling
	if error != nil {
		fmt.Println("Error generating key during encryptAttachment")
		return "", "", error
	}

	// Open input file
	inFile, err := os.Open(plaintextFilePath)
	if err != nil {
		fmt.Println("Error opening file for encryptAttachment")
		return "", "", err
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.Create(ciphertextFilePath)
	if err != nil {
		return "", "", err
	}
	defer outFile.Close()

	textPt, err := io.ReadAll(inFile)
	if err != nil {
		fmt.Print("error reading from file")
	}

	// Create a new ChaCha20 stream cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
	if err != nil {
		return "", "", err
	}

	ctext := make([]byte, len(textPt))

	cipher.XORKeyStream(ctext, textPt)

	_, err = outFile.Write(ctext)
	if err != nil {
		fmt.Println("Error printing to output file in encryptAttachment")
	}

	// What does file hash mean lol

	h := sha256.Sum256(ctext)
	hexH := hex.EncodeToString(h[:])
	hexEncodedKey, err := hex.DecodeString(string(key))
	return hexH, string(hexEncodedKey), err
}

func decodePrivateSigningKey(privKey PrivKeyStruct) ecdsa.PrivateKey {

	// TODO: Implement

	var result ecdsa.PrivateKey

	keyBytes, err := b64.StdEncoding.DecodeString(privKey.SigSK)
	if err != nil {
		fmt.Println("Failed to decode privKey.SigSK in decodePrivateSigningKey")
		return result
	}

	// Parse the PKIX public key
	parsedPSK, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		fmt.Println("Failed to ParsePKCS8PrivateKey in decodePrivateSigningKey")
		return result
	}

	// Type assert to ecdsa.PublicKey
	privateKey, ok := parsedPSK.(*ecdsa.PrivateKey)
	if !ok {
		fmt.Println("Failed to assert type *ecdsa.PrivateKey in decodePrivateSigningKey")
		return result
	}

	result = *privateKey

	return result
}

// Sign a string using ECDSA
func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
	// TODO: Implement

	decodedKey := decodePrivateSigningKey(privKey)

	signed, err := ecdsa.SignASN1(rand.Reader, &decodedKey, message)
	if err != nil {
		fmt.Println("Failed to ECDSA Sign in ECDSASign")
		return nil
	}

	return signed
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func decryptMessage(payload string, senderUsername string, senderPubKey *PubKeyStruct, recipientPrivKey *PrivKeyStruct) ([]byte, error) {

	b64payload, err := b64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println("Error 1 in decryptMessage")
		return nil, err
	}

	var parsedPayload CiphertextStruct
	err = json.Unmarshal(b64payload, &parsedPayload)
	if err != nil {
		fmt.Println("Error 2 in decryptMessage")
		return nil, err
	}

	// Create toVerify
	toVerify := parsedPayload.C1 + parsedPayload.C2

	// Decode Sender's Public Signing Key
	preParsedDecodedPublicKey, err := b64.StdEncoding.DecodeString(senderPubKey.SigPK)
	if err != nil {
		fmt.Println("Error 3 in decryptMessage")
		return nil, err
	}

	preCheckedDecodedPublicKey, err := x509.ParsePKIXPublicKey(preParsedDecodedPublicKey)
	if err != nil {
		fmt.Println("Error 4 in decryptMessage")
		return nil, err
	}

	senderPublicSigningKey, ok := preCheckedDecodedPublicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Error 5 in decryptMessage")
		return nil, err
	}

	// Sender Public Signing Key is an ecdsa.PublicKey
	toVerifyHash := sha256.Sum256([]byte(toVerify))

	// Base64 Decode Signature
	decodedSignature, err := b64.StdEncoding.DecodeString(parsedPayload.Sig)
	if err != nil {
		fmt.Println("Error 6 in decryptMessage")
		return nil, err
	}

	// Verify the signature
	ok = ecdsa.VerifyASN1(senderPublicSigningKey, toVerifyHash[:], decodedSignature)
	if !ok {
		fmt.Println("Signature Verification Failed")
		return nil, err
	}

	// Decode Sender's Encryption Public Key
	notParsedDecodedC1, err := b64.StdEncoding.DecodeString(parsedPayload.C1)
	if err != nil {
		fmt.Println("Error 7 in decryptMessage")
		return nil, err
	}

	parsedSenderPK, err := x509.ParsePKIXPublicKey(notParsedDecodedC1)
	if err != nil {
		fmt.Println("Error 8 in decryptMessage")
		return nil, err
	}

	// Decoded encPK
	SenderPKRSA, ok := parsedSenderPK.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Error 9 in decryptMessage")
		return nil, err
	}

	SenderEncPK, err := SenderPKRSA.ECDH()
	if err != nil {
		fmt.Println("Error 10 in decryptMessage")
		return nil, err
	}

	// Decrypt Recipient Private Encryption Key
	privateRecipEncKey, err := b64.StdEncoding.DecodeString(recipientPrivKey.EncSK)
	if err != nil {
		fmt.Println("Error 11 in decryptMessage")
		return nil, err
	}

	privateRecipEncryptionKeyPreCheck, err := x509.ParsePKCS8PrivateKey(privateRecipEncKey)
	if err != nil {
		fmt.Println("Error 12 in decryptMessage")
		return nil, err
	}

	PrivateEncryptionKeyECDSA, ok := privateRecipEncryptionKeyPreCheck.(*ecdsa.PrivateKey)
	if !ok {
		fmt.Println("Error 13 in decryptMessage")
		return nil, err
	}

	RecipientEncSK, err := PrivateEncryptionKeyECDSA.ECDH()
	if err != nil {
		fmt.Println("Error 14 in decryptMessage")
		return nil, err
	}

	// Shared Secret Key, Recipient Private Key, Sender Public Key
	val, err := RecipientEncSK.ECDH(SenderEncPK)
	if err != nil {
		fmt.Println("Error 15 in decryptMessage")
		return nil, err
	}

	// Shared Secret Key?
	k := sha256.Sum256(val)

	// Decode C2
	DecodedC2, err := b64.StdEncoding.DecodeString(parsedPayload.C2)
	if err != nil {
		fmt.Println("Error 16 in decryptMessage")
		return nil, err
	}

	// Decode ChaCha
	stream, err := chacha20.NewUnauthenticatedCipher(k[:], make([]byte, chacha20.NonceSize))

	decryptedMessage := make([]byte, len(DecodedC2))

	stream.XORKeyStream(decryptedMessage, DecodedC2)

	// Parse M'
	originalMessageLength := len(decryptedMessage) - 4

	// Compute Check
	originalMessage := decryptedMessage[:originalMessageLength]
	originalChecksum := decryptedMessage[originalMessageLength:]
	computedChecksum := crc32.ChecksumIEEE(originalMessage)

	// Turn checkSum into bytes
	computedChecksumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(computedChecksumBytes, computedChecksum)

	/*
		if !bytes.Equal(computedChecksumBytes, originalChecksum) {
			fmt.Println("Rejected: 1")
			return nil, err
		}
	*/

	// Compute Username Check

	indexOfColon := bytes.IndexByte(originalMessage, 0x3A)

	username := originalMessage[:indexOfColon]

	if !bytes.Equal(username, []byte(senderUsername)) {
		fmt.Println("Rejected: 2")
		return nil, err
	}

	return originalMessage[indexOfColon+1:], err
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct) []byte {
	// TODO: IMPLEMENT

	// Decode recipient's public key as a point on the P-256 curve
	encPKBytes, err := b64.StdEncoding.DecodeString(pubkey.EncPK)
	if err != nil {
		fmt.Println("Error 1 in encryptMessage")
		return nil
	}

	// Parse the PKIX public key (returns ECDSA public key)
	parsedEncPK, err := x509.ParsePKIXPublicKey(encPKBytes)
	if err != nil {
		fmt.Println("Error 2 in encryptMessage")
		return nil
	}

	// Type assert to *ecdsa.PublicKey
	decodedEncPKRSA, ok := parsedEncPK.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Error 3 in encryptMessage")
		return nil
	}

	// DecodedEncPK is the recipient's public key
	RecipientEncPK, err := decodedEncPKRSA.ECDH()
	if err != nil {
		fmt.Println("Error 4 in EncryptMessage")
	}

	// Decode encSK, sender's private key
	encSKBytes, err := b64.StdEncoding.DecodeString(globalPrivKey.EncSK)
	if err != nil {
		fmt.Println("Error 5 in EncryptMessage")
	}

	parsedEncSK, err := x509.ParsePKCS8PrivateKey(encSKBytes)
	if err != nil {
		fmt.Println("Error 6 in EncryptMessage")
	}

	decodedEncSKRSA, ok := parsedEncSK.(*ecdsa.PrivateKey)
	if !ok {
		fmt.Println("Error 7 in EncryptMessage")
		return nil
	}

	SenderEncSK, err := decodedEncSKRSA.ECDH()
	if err != nil {
		fmt.Println("Error 8 in EncryptMessage")
	}

	// decodedEncSK = Sender's Encryption Private Key
	// decodedEncPK = Recipient's Encryption Public Key

	// Shared Secret Key: Sender's private key, Recipient Public Key
	ssk, err := SenderEncSK.ECDH(RecipientEncPK)
	if err != nil {
		fmt.Println("Error 9 in EncryptMessage")
	}

	// sha256(ssk)?
	k := sha256.Sum256(ssk)

	// Encode Sender's Encryption Public Key into C1
	C1 := globalPubKey.EncPK

	// Now compute C2

	// Check if the colon character (0x3A) is present in the sender's username
	if strings.Contains(senderUsername, ":") {
		fmt.Print("Username contains :")
		return nil
	}

	// Construct the message string M'
	concatenatedMessage := senderUsername + string(byte(0x3A)) + string(message)

	// Define the polynomial for CRC32 (IEEE)
	checksum := crc32.ChecksumIEEE([]byte(concatenatedMessage))
	checksumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumBytes, checksum)

	// Concatenate the message and the checksum (???)
	concatenatedMessageBytes := append([]byte(concatenatedMessage), checksumBytes...)

	// ChaCha20 (concatenatedMessage is M'')
	cipherstream, err := chacha20.NewUnauthenticatedCipher(k[:], make([]byte, chacha20.NonceSize))
	if err != nil {
		fmt.Println("Error 11 in EncryptMessage")
	}

	// Stream cipher things
	ciphertext := make([]byte, len(concatenatedMessageBytes))
	cipherstream.XORKeyStream(ciphertext, concatenatedMessageBytes)

	// Encode the ciphertext using BASE64
	C2 := b64.StdEncoding.EncodeToString(ciphertext)

	// Signing starts here
	toSign := C1 + C2

	// Hash Message before Signing
	toSignHash := sha256.Sum256([]byte(toSign))

	// Sign Message
	signingPrivateKey := decodePrivateSigningKey(globalPrivKey)

	signedMessagePreEncoding, err := ecdsa.SignASN1(rand.Reader, &signingPrivateKey, toSignHash[:])

	// Encode signed message
	signedMessage := b64.StdEncoding.EncodeToString(signedMessagePreEncoding)

	// Construct Ciphertext
	ct := CiphertextStruct{
		C1:  C1,
		C2:  C2,
		Sig: signedMessage,
	}

	jsonText, err := json.Marshal(ct)
	if err != nil {
		fmt.Println("Error 12 in EncryptMessage")
	}

	return jsonText
}

// Decrypt a list of messages in place
func decryptMessages(messageArray []MessageStruct) {
	for i := range messageArray {

		senderPubKey, _ := getPublicKeyFromServer(messageArray[i].From)

		if messageArray[i].ReceiptID == 0 && len(messageArray[i].Payload) > 0 && messageArray[i].url == "" {

			decryptedMessage, err := decryptMessage(messageArray[i].Payload, messageArray[i].From, senderPubKey, &globalPrivKey)

			if err != nil {
				fmt.Print("Unable to decrypt message: ", err)
			} else {
				messageArray[i].decrypted = string(decryptedMessage)

				// Send read receipt
				sendMessageToServer(username, messageArray[i].From, []byte(""), messageArray[i].Id)
			}
		} else {
			fmt.Println("got read receipt")
		}
	}
}

// Download any attachments in a message list
func downloadAttachments(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		return
	}

	os.Mkdir(attachmentsDir, 0755)

	// Iterate through the array, checking for attachments
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].url != "" {
			// Make a random filename
			randBytes := make([]byte, 16)
			rand.Read(randBytes)
			localPath := filepath.Join(attachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")

			err := downloadFileFromServer(messageArray[i].url, localPath)

			senderPubKey, _ := getPublicKeyFromServer(messageArray[i].From)

			// Decrypt the Message
			decryptedMessage, err := decryptMessage(messageArray[i].Payload, messageArray[i].From, senderPubKey, &globalPrivKey)
			if err != nil {
				fmt.Print("Error 2 in Download Attachments")
			} else {
				messageArray[i].decrypted = string(decryptedMessage)
			}

			// Decrypt the DecryptedMessage
			// Extracting fileURL
			fileURLStart := strings.Index(messageArray[i].decrypted, "<") + 1
			fileURLEnd := strings.Index(messageArray[i].decrypted, ">")
			fileURL := messageArray[i].decrypted[fileURLStart:fileURLEnd]

			// Extracting hexKey
			hexKeyStart := strings.Index(messageArray[i].decrypted, "KEY=<") + 5
			hexKeyEnd := strings.Index(messageArray[i].decrypted, ">?H=")
			hexKey := messageArray[i].decrypted[hexKeyStart:hexKeyEnd]

			// Extracting hash
			hashStart := strings.Index(messageArray[i].decrypted, "H=<") + 3
			hashEnd := len(messageArray[i].decrypted) - 1
			hash := messageArray[i].decrypted[hashStart:hashEnd]

			// Check URL
			if fileURL != messageArray[i].url {
				fmt.Println("Rejection of URL")
				// Delete File
			}

			// Open File Contents
			inFile, err := os.Open(localPath)
			if err != nil {
				fmt.Println("Error 3 in Download Attachments")
				return
			}

			textCt, err := io.ReadAll(inFile)
			if err != nil {
				fmt.Print("Error 4 in Download Attachments")
			}

			inFile.Close()

			// Check Hash

			decodedHash, err := hex.DecodeString(hash)
			var originalHash [32]byte
			copy(originalHash[:], decodedHash)
			checkHash := sha256.Sum256(textCt)
			if originalHash != checkHash {
				fmt.Println("Hashes do not match in Download Attachments")
				return
			}

			// Create Key
			key, err := hex.DecodeString(hexKey)

			// Decrypt File
			c, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))

			// Decrypt the ciphertext
			plaintext := make([]byte, len(textCt))
			c.XORKeyStream(plaintext, textCt)

			// Write to file

			file, err := os.OpenFile(localPath, os.O_WRONLY|os.O_TRUNC, 0666)
			defer file.Close()

			_, err = file.Write(plaintext)

			if err == nil {
				messageArray[i].localPath = localPath
			} else {
				fmt.Println(err)
			}
		}
	}
}

// Print a list of message structs
func printMessageList(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		fmt.Println("You have no new messages.")
		return
	}

	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
	// Iterate through the array, printing each message
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].ReceiptID != 0 {
			fmt.Printf("Read receipt\n")
			continue
		}

		fmt.Printf("From: %s\n\n", messageArray[i].From)

		fmt.Printf(messageArray[i].decrypted)
		if messageArray[i].localPath != "" {
			fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].localPath)
		} else if messageArray[i].url != "" {
			fmt.Printf("\n\tAttachment download failed\n")
		}
		fmt.Printf("\n-----------------------------\n\n")
	}
}

// Print a list of user structs
func printUserList(userArray []UserStruct) {
	if len(userArray) == 0 {
		fmt.Println("There are no users on the server.")
		return
	}

	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

	// Get current Unix time
	timestamp := time.Now().Unix()

	// Iterate through the array, printing each message
	for i := 0; i < len(userArray); i++ {
		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
			fmt.Printf("* ")
		} else {
			fmt.Printf("  ")
		}

		fmt.Printf("%s\n", userArray[i].Username)
	}
	fmt.Printf("\n")
}

func getTempFilePath() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}

// Generate a fresh public key struct, containing encryption and signing keys
func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
	// This is somewhat confidently complete - ish

	var pubKey PubKeyStruct
	var privKey PrivKeyStruct

	// Generate Keys for Encryption Keys
	enc, err := ecdh.Curve.GenerateKey(ecdh.P256(), rand.Reader)
	if err != nil {
		return pubKey, privKey, nil
	}

	// Encode Private Key Enc and Set Value
	arrBytes, err := x509.MarshalPKCS8PrivateKey(enc)
	if err != nil {
		return pubKey, privKey, nil
	}
	privKey.EncSK = b64.StdEncoding.EncodeToString(arrBytes)

	// Encode Public Key Enc and Set Value
	arrBytes, err = x509.MarshalPKIXPublicKey(enc.PublicKey())
	if err != nil {
		return pubKey, privKey, nil
	}
	pubKey.EncPK = b64.StdEncoding.EncodeToString(arrBytes)

	// Generate new key for signing keys
	sig, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pubKey, privKey, nil
	}

	// Encode Signing Key sigSK
	arrBytes, err = x509.MarshalPKCS8PrivateKey(sig)
	if err != nil {
		return pubKey, privKey, nil
	}
	privKey.SigSK = b64.StdEncoding.EncodeToString(arrBytes)

	// Encode Signing Key sigPK
	arrBytes, err = x509.MarshalPKIXPublicKey(sig.Public())
	if err != nil {
		fmt.Println("Failed to encode sig.PublicKey in GeneratePublicKey")
		return pubKey, privKey, nil
	}
	pubKey.SigPK = b64.StdEncoding.EncodeToString(arrBytes)

	globalPubKey = pubKey
	globalPrivKey = privKey

	return pubKey, privKey, nil
}

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	flag.IntVar(&serverPort, "port", 8080, "port for the server")
	flag.StringVar(&serverDomain, "domain", "localhost", "domain name for the server")
	flag.StringVar(&username, "username", "alice", "login username")
	flag.StringVar(&password, "password", "abc", "login password")
	flag.StringVar(&attachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	flag.BoolVar(&noTLS, "notls", false, "use HTTP instead of HTTPS")
	flag.BoolVar(&strictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	flag.BoolVar(&doUserRegister, "reg", false, "register a new username and password")
	flag.BoolVar(&headlessMode, "headless", false, "run in headless mode")
	flag.StringVar(&attackFile, "attack", "", "run in attack mode")
	flag.StringVar(&victimUsername, "victim", "alice", "victim username")
	flag.Parse()

	// Set the server protocol to http or https
	if noTLS == false {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}

	// If self-signed certificates are allowed, enable weak TLS certificate validation globally
	if strictTLS == false {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set up the server domain and port
	serverDomainAndPort = serverDomain + ":" + strconv.Itoa(serverPort)

	// Attack command loop
	if attackFile != "" {

		recoveredPlainText := ""

		// Read the contents of the file
		cipherText, err := os.ReadFile(attackFile)
		if err != nil {
			fmt.Println("Error opening ciphertext file for attack")
			return
		}

		// Parse MessageStruct
		var recoveredMessageStruct MessageStruct
		err = json.Unmarshal(cipherText, recoveredMessageStruct)
		sender := recoveredMessageStruct.From
		intendedRecipient := recoveredMessageStruct.To
		payload := recoveredMessageStruct.Payload

		// Parse the ciphertext
		b64payload, err := b64.StdEncoding.DecodeString(string(payload))
		var parsedCipherText CiphertextStruct
		err = json.Unmarshal(b64payload, &parsedCipherText)

		C1, err := b64.StdEncoding.DecodeString(parsedCipherText.C1)
		C2, err := b64.StdEncoding.DecodeString(parsedCipherText.C2)
		modifiedUsername := sender

		// Begin for loop for length of message...?

		for i := 1; i < (len([]byte(sender)) - 4); i++ {

			// Modify ciphertext (change the below command)
			for j := 1; j < i; j++ {
				modifiedUsername = modifiedUsername + ":"
			}
			usernameLength := len([]byte(modifiedUsername))

			// Register new username
			err = registerUserWithServer(modifiedUsername, password)
			newAPIkey, err := serverLogin(modifiedUsername, password)
			if err != nil {
				fmt.Println("Error logging in server for attack")
				return
			}

			// New API key?
			apiKey = newAPIkey

			// Create new keys
			globalPubKey, globalPrivKey, err = generatePublicKey()
			_ = globalPrivKey // This suppresses a Golang "unused variable" error

			locationOfXORByte := usernameLength + 1
			originalByte := C2[locationOfXORByte]

			// Nested for loop...?
			for b := 0x01; b <= 0xFF; b++ {

				// XOR b with the character after the :
				C2[locationOfXORByte] = originalByte ^ byte(b)

				// Re-Sign
				// Signing starts here
				toSign := b64.StdEncoding.EncodeToString(C1) + b64.StdEncoding.EncodeToString(C2)

				// Hash Message before Signing
				toSignHash := sha256.Sum256([]byte(toSign))

				// Sign Message
				signingPrivateKey := decodePrivateSigningKey(globalPrivKey)

				signedMessagePreEncoding, err := ecdsa.SignASN1(rand.Reader, &signingPrivateKey, toSignHash[:])
				if err != nil {
					fmt.Println("Error signing for attack")
					return
				}

				signedMessage := b64.StdEncoding.EncodeToString(signedMessagePreEncoding)

				// Redo Ciphertext
				reEncodedCipherText := CiphertextStruct{
					C1:  b64.StdEncoding.EncodeToString(C1),
					C2:  b64.StdEncoding.EncodeToString(C2),
					Sig: signedMessage,
				}
				SendingModifiedCipherText, err := json.Marshal(reEncodedCipherText)

				// Send to Alice
				sendMessageToServer(username, intendedRecipient, []byte(SendingModifiedCipherText), 0)

				// See if Decrypted
				messageList, err := getMessagesFromServer()
				if len(messageList) > 0 {
					recoveredPlainText += string(byte(':') ^ byte(b))
					break
				}
			}
		}
		fmt.Println(recoveredPlainText)
		return
	}

	// If we are registering a new username, let's do that first
	if doUserRegister == true {
		fmt.Println("Registering new user...")
		err := registerUserWithServer(username, password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
	}

	// Connect and log in to the server
	fmt.Print("Logging in to server... ")
	newAPIkey, err := serverLogin(username, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	apiKey = newAPIkey

	// Geerate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err := generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(username, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}

	// Main command loop
	fmt.Println("Jmessage Go Client, enter command or help")
	for running == true {
		var input string
		var err error

		// If we're not in headless mode, read a command in
		if headlessMode == false {
			fmt.Print("> ")

			input, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}
		} else {
			// Headless mode: we always sleep and then "GET"
			time.Sleep(time.Duration(100) * time.Millisecond)
			input = "GET"
		}

		parts := strings.Split(input, " ")
		//fmt.Println("got command: " + parts[0])
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "SEND":
			if len(parts) < 2 {
				fmt.Println("Correct usage: send <username>")
			} else {
				err = doReadAndSendMessage(strings.TrimSpace(parts[1]), "")
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "GET":
			messageList, err := getMessagesFromServer()
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				downloadAttachments(messageList)
				printMessageList(messageList)
			}
		case "LIST":
			userList, err := getUserListFromServer()
			if err != nil {
				fmt.Print("Unable to fetch user list: ")
				fmt.Print(err)
			} else {
				printUserList(userList)
			}
		case "ATTACH":
			if len(parts) < 3 {
				fmt.Println("Correct usage: attach <username> <filename>")
			} else {
				// We have username and filename
				recipient := strings.TrimSpace(parts[1])
				filename := strings.TrimSpace(parts[2])

				// Temporary File Path
				encFilePath := getTempFilePath()

				// Encrypt File
				hexKey, hash, err := encryptAttachment(filename, encFilePath)
				if err != nil {
					fmt.Println("Failed to encrypt attachment in main")
				}

				// Upload encrypted file, get URL
				fileURL, err := uploadFileToServer(encFilePath)
				if err != nil {
					fmt.Println("Failed to upload encrypted attachment in main")
				}

				// Format String and Send Message
				attachmentString := ">>>MSGURL=<" + fileURL + ">?KEY=<" + hexKey + ">?H=<" + hash + ">"

				sendAttachmentToServer(username, recipient, []byte(attachmentString), 0, fileURL, encFilePath)
			}
		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tquit - exit")

		default:
			fmt.Println("Unrecognized command")
		}
	}
}
