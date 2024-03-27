# JMessage Specification

This specification defines the cryptographic and binary interface for an end-to-end encrypted messaging application. 
A JMessage implementation consists of a server and one or more clients that interoperate to send encrypted messages
and file attachments. 

JMessage was designed for teaching purposes, and hence it was deliberately designed to include potentially vulnerable, obsolete cryptography. While you are free to expand on the current design and improve it, you should not use this for
critical data.

## Overview

A JMessage deployment consists of two components: (1) a JMessage server, and (2) one or more JMessage clients, 
which interoperate with the server to exchange messages with other clients. Each JMessage client generates its own cryptographic keypairs 
internally; the secret keys never leave the client. All messages are encrypted end-to-end to the receiving clients. 
This design ensures that even a curious server operator will not not see the content of the messages.

**The JMessage Client.** Each JMessage client interacts with the server using an HTTPS-based RESTful API. It is responsible for 
interacting with the user, generating cryptographic keys, encrypting messages sent to other users, and decrypting messages 
received from other users. The client may also display information such as the cryptographic key fingerprint of another user.

**The JMessage Server.** The JMessage server does not implement any cryptographic functions except for realizing an HTTPS-secured 
connection. It interacts with the clients via HTTPS to provide a simple API for the following functions:

1. Signup/registration of new user IDs
2. Listing all users registered on the server
3. Uploading public keys
4. Public key lookup
5. Message upload to a mailbox
7. Retrieval of mailbox contents
8. Attachment upload
9. Retrieval of attachments

The reference implementation of the JMessage server is written as a Python/Flask application; a copy of the source and usage instructions can be found in the main repository so you can run it yourself. The instructors will also 
provide a master copy of the server so that the class can use this to interact with each other.

## A typical JMessage interaction (informative)

Full details of the JMessage specification are given in later sections. This section gives a brief overview of what a JMessage interaction looks like. 

Each JMessage client must register a username and password with the server. It then subsequently generates and
uploads a public key for encryption. More concretely:

1. The client registers a username and password with the server (`/registerUser/`)
2. The client generates public and secret key material.
3. The client logs into the server using its username and password (`/login/`) to obtain an API key.
4. The client uploads its public key to the server (`/uploadKey/`).

JMessage messages can have three formats:

1. A standard message contains encrypted unstructured text.
2. An *attachment message* contains encrypted text embedding the URL of an attachment file, as well as a decryption key and file hash.
3. A *read receipt* message contains no encrypted material. It indicates that a message was received and decrypted by a counterparty.

To send an encrypted message:

1. The sender's client calls the server to obtain the recipient's public key (`/lookupKey/`).
4. The sender encrypts their message using the recipient's public key, then signs it.
5. The sender uploads the BASE64-encoded ciphertext (`/sendMessage/`).
6. At a later point, the recipient downloads a list of new messages (`/getMessages/`).
7. For each message, the recipient decrypts the message and verifies the sender's signature.
9. The recipient sends back a read-receipt message for each _correctly-decrypted_ (non-read-receipt) message.
10. The server deletes all downloaded messages.

Attachments are included as follows:

1. The sender's client generates a random encryption key, then encrypts the attachment file, then hashes the result.
2. The sender uploads the encrypted file to the server, and obtains a URL (`/uploadFile/`).
3. The sender formulates a standard encrypted message, where the message plaintext contains URL, key, hash.
4. When the recipient receives this message, it downloads the attachment, checks the hash, and decrypts the file.

## Interacting with the JMessage server

The JMessage server supports several functions: new user signup, public key registration, public key lookup, message delivery, message lookup, 
attachment upload, attachment lookup, as well as a function to list all registered usernames. Requests and responses are transmitted using standard HTTP GET 
or POST requests with JSON encoding used to transmit data structures. The demo server will include a valid HTTPS certificate, but when using your own 
test servers you will need to disable certificate verification at the client.

### User signup

To register a new user account, issue a GET request with the following structure:

```
/registerUser/<username>/<password>
```

The parameters `<username>` and `<password>` represent the username and assigned password for this account. If the account already exists, 
the server will return HTTP response 409 (CONFLICT). Otherwise it will return HTTP response code 200 (SUCCESS).

There is currently no way to remove accounts or change passwords.

### User login

To log in to the server with a registered username and password, issue a GET request with the following structure:

```
/login/<username>/<password>
```

The parameters `<username>` and `<password>` represent the username and assigned password for this account. If the credentials are 
invalid, the server will return HTTP response code 401 (UNAUTHORIZED). If the credentials are valid, the server will return HTTP 
response code 200 (SUCCESS) and the following JSON structure:

```
{
  "APIkey": "<APIKeyValue>"
}
```

Here `<APIKeyValue>` is an alphanumeric API string that you will pass to the server for all subsequent operations. The server will 
retain this value in its memory until it reboots or times out the login session, at which point you will need to execute the login command again. 
You are allowed repeat server login as many times as you want, even if you are already logged in.

### User listing

To obtain a JSON list of all user accounts, issue a GET request with the following structure:

```
/listUsers
```

This will return a JSON list of all users on the system, each containing the fields ``(username, creationTime, lastCheckedTime)``. The latter
two arguments are UNIX-style timestamps.

```
[
  {
    "username": "<string>"
    "creationTime": <int>
    "lastCheckedTime": <int>
  },
  {
    "username": "<string>"
    "creationTime": "<int>"
    "lastCheckedTime": <int>
  },
  ...
]
```

### Public key registration

To assign a public key to this account, issue a POST request with the following structure:

```
/uploadKey/<username>/<apikey>
```

The public key content is a `pubkey` JSON object uploaded via POST. It contains the following fields:

```
{
  "encPK": "<Encryption public key (BASE64-encoded)>",
  "sigPK": "<Signing public key (BASE64-encoded)>"
}
```

Each field should contain a BASE64-encoded public key for (respectively) encryption and signature verification. Any previous public 
key registered to the account will be overwritten. The server will return HTTP response 401 (UNAUTHORIZED) if the credentials
are incorrect. Otherwise it will return HTTP response code 200 (SUCCESS).

### Public key lookup

Any user can look up the public key associated with a user account. This does not require the caller to be logged in. To obtain a public 
key, issue a GET request with the following structure:

```
/lookupKey/<username_to_lookup>
```

Here `<username_to_lookup>` contains the username of the user to be looked up. This call will return a `pubkey` object with the structure given 
in the previous section, or it will return an HTTP error response 404 (NOT FOUND) if the user is not identified, or if the user has not 
uploaded a public key.

### Message upload

A registered user can upload a new message to another user. Messages must be BASE64-encoded and have a size limit of 
2048 bytes in BASE64 encoding. To upload a message, issue a POST request with the following structure:

```
/sendMessage/<username>/<apikey>
```

As before, `<username>` contains the username of the sender and `<apikey>` their password. 

The message content is a `message` JSON object uploaded via POST, and it has the following fields:

* `from`: Sender username (string). _This must exactly match the username given in the POST request._
* `to`: Receipient username (string).
* `id`: Message identifier (integer), must not repeat for a given sender.
* `receiptID`: 0 for standard messages. If the message is a read-receipt, this will identify which message it references (integer).
* `payload`: JSON payload of the message (base64-encoded JSON object containing fields `C1`, `C2`, `Sig`). Empty for read-receipts.

The message identifier `id` is an integer chosen by the sending party. For messages containing encrypted content, the `receipt` field should 
be set to `0`, and the `payload` field should contain a ciphertext. For read-receipt messages, the `receipt` field should contain the message 
ID of the message being acknowledged, and `payload` should be set to `null`. 

Clients should always send read-receipts in response to valid encrypted messages. However, they should never transmit a receipt if message
decryption fails, or in response to another read-receipt message.

If the recipient cannot be located, this call returns HTTP error response 404 (NOT FOUND). If the  user's mailbox is full, this call 
returns HTTP error response 429 (TOO_MANY_REQUESTS).

Attachment messages will contain the encrypted string `>>>MSGURL=<url>` where `<url>` points to an encrypted attachment URL.

### Message retrieval

A registered user can request a list of all messages waiting in their mailbox. Once requested, the messages 
will be deleted from the mailbox.

```
/getMessages/<username>/<apikey>
```

Messages are returned as an array of JSON structures identical to the structures uploaded by users in the previous section.

### Attachment upload

A registered user can upload a file to the server at a temporary URL. To do this, the client makes 
a form POST request with the following structure:

```
/uploadFile/<username>/<apikey>
```

The file should be included as a multipart MIME FORM file with the fields `filefield` and data of type `application/octet-stream`.
An example of the raw data for a file is included below:

```
b'--c5df8a4935bda876fa80dab56e1da8ece5f3f48cbaa7e955a42c63d33450\r\nContent-Disposition: form-data; name="filefield"; filename="test.txt"\r\nContent-Type: application/octet-stream\r\n\r\nThis is a test file!\n\r\n--c5df8a4935bda876fa80dab56e1da8ece5f3f48cbaa7e955a42c63d33450--\r\n'
```

There is a maximum file size of 100 KB. Once the file is accepted, the server will generate a unique file path of the form 
`/<username>/<random filename>.dat` and return status code 200. This path will be returned in a JSON object with the following structure:

```
{
  "path": "<path to the file>"
}
```

A full download URL can be constructed from the returned value `<path>` as follows:

```
url = http[s]://serverdomain:port/downloadFile/<path>
```

If upload fails, the server will return an error code 400 or 401 (`UNAUTHORIZED`).

### Attachment retrieval

Any user can obtain a file by issuing a GET request structured as follows:

```
/downloadFile/<path>
```

The string `<path>` will contain the path returned by the `uploadFile` call. This will return success (200), or an error
401 or 404 (if the file is not found.)

## JMessage Encryption

### Overview

JMessage uses three cryptographic primitives: Elliptic Curve Diffie-Hellman with the NIST P-256 curve, ChaCha20 encryption and ECDSA signing using the P-256 elliptic curve.

Each client is responsible for generating and maintaining two long-term keypairs: a P-256 elliptic curve keypair `encPK, encSK` and a P-256 ECDSA signing keypair `sigPK, sigSK`. These keys may be generated each time the client starts up, or the client may generate them one time and store the keys 
persistently on disk. The public keys `encPK, sigPK` are encoded to binary octet-strings using standard encodings described further below. They are then individually BASE64-encoded and sent to the server as a JSON structure. The secret keys are never sent to the server.

The encryption procedure is described in the following section. The output of the procedure is three binary octet strings `C1`, `C2`, `Sig`. These are subsequently encoded using BASE64 and placed into a JSON structure as follows. This structure forms the `payload` component used in message upload and download. 

```
{
  "C1": "<BASE64-encoded ciphertext>",
  "C2": "<BASE64-encoded ciphertext>",
  "Sig": "<BASE64-encoded signature>"
}
```

Upon receiving a message of the above form, a recipient first looks up the sender's public key `encPK, sigPK` on the server, and then uses `sigPK` to verify a signature on the message, and decrypts the message with its own secret key.

The following sections give precise step-by-step instructions for each process.

### Generating public keys

To generate a new set of client keys. Let `P` be the generator of P-256 subgroup, where
`q` is the order of `P`. We use the notation `xP` or `x*P` to indicate [scalar point multiplication](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication) of `P` by the scalar `x`.

1. Generate a random scalar `a` between `0` and `q-1` (inclusive).
2. Use [PKCS8 encoding (Section 5)](https://datatracker.ietf.org/doc/html/rfc5208#section-5)* to encode `a` as `encSK`.
3. Compute `pk = aP`. Use [RFC 5208, Section 4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1))* to encode `pk` as `encPK`.
4. Generate a random scalar `b` between `0` and `q-1` (inclusive).
5. Use [PKCS8 encoding (Section 5)](https://datatracker.ietf.org/doc/html/rfc5208#section-5)* to encode `b` as `sigSK`.
6. Compute `vk = bP`. Use [RFC 5208, Section 4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1))* to encode `vk` as `sigPK`.

* Note: both PKCS8 private key encoding and RFC 5208 public key encoding are implemented by default in the [Go ECDH package](https://pkg.go.dev/crypto/ecdh) within the PublicKey and PrivateKey classes, and we recommend using this implementation.

### Encrypting messages

Let `M` be an octet-string plaintext, let `encPK` be a (BASE64-decoded) recipient public key. Let `sender_username` be the sender's username, and let `sigSK` be the (BASE64-decoded secret key.) The encryption procedure breaks into three stages:

Compute `C1` and `K`:

1. The sender decodes `encPK` as a point on the P-256 elliptic curve.
2. The sender generates a random scalar `c` between `0` and `q-1` (inclusive).
3. The sender computes `epk = cP` using scalar point multiplication.
4. The sender computes `ssk = c*encPK` where * represents scalar point multiplication, and encodes the x-coordinate according to SEC 1, Version 2.0, Section 2.3.5. (NB: This is natively implemented as the ECDH() method in Go's crypto.ecdh.)
// Version 2.0, Section 2.3.5.
5. The sender computes `K = SHA256(ssk)` where * represents scalar point multiplication. This key `K` will be used in the next section.
6. The sender encodes `epk` into the value `C1`, by first encoding it using [RFC 5208, Section 4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1) and then BASE64-encoding the result.

Compute `C2`:

1. The sender first constructs a message string `M' = sender_username || 0x3A || M` where `||` represents concatenation, and the byte `0x3A` does not appear in the sender username.
2. The sender computes `CHECK = CRC32(M')`, where CRC32 uses the IEEE standard polynomial (0xedb88320).
3. The sender constructs a message string `M'' = M' || CHECK`.
4. The sender uses ChaCha20 with an initial state/IV set to 0 to encipher `M''` under key `K`. It encodes the result using BASE64 to produce `C2`.

Compute `Sig`:

1. The sender concatenates `C1` and `C2` to form a string `toSign`.
2. The sender decodes its private signing key `sigSK`.
3. The sender signs the string `toSign` using ECDSA with P-256 under key `sigSK`, and encodes the resulting signature using BASE64 to produce `Sig`.

### Decrypting messages

Let `(C1, C2, Sig)` be a ciphertext, where each element has been BASE64 decoded. Let `sender_username` be the username of the purported sender, let `encSK` be the (BASE64-decoded) recipient's secret key, and let `sigPK` be the (BASE64-decoded) sender's public key, obtained from the server.

To decrypt a message, the recipient performs the following tasks.

Verify the signature `Sig`:

1. The recipient concatenates `C1` and `C2` to form a string `toVerify`.
2. The recipient decodes `sigPK` into an ECDSA public key (point on P-256).
3. The recipient verifies the signature `Sig` against message `toVerify` using ECDSA with P-256 under key `sigPK`.
4. If the previous check fails, terminate processing and reject.

Decrypt `C1` to obtain `K`:

1. The recipient BASE64-decodes `C1` as a point on P-256.
2. The recipient decodes `encSK` as a scalar `s` between `0` and `q-1` (inclusive).
3. The recipient computes `K = SHA256(s * C1)` where * represents scalar point multiplication.

Decrypt `C2` to obtain the plaintext:

1. The recipient BASE46-decodes `C2` as an octet string.
2. The recipient deciphers `C2` using ChaCha20 under `K`, using a zero IV to obtain `M'`.
3. The recipient parses `M'` as `username || 0x3A || M || CHECK`, where CHECK is a 4-byte octet string.
4. The recipient computes `CHECK' = CRC32(username || 0x3A || M )`. If `CHECK != CHECK'`, abort decryption and reject.
5. If `username != sender_username`, then abort decryption and reject.
6. Otherwise, output `M`.

### Sending read receipts

Once a client has successfully decrypted an encrypted message or attachment message, it should send a read receipt back to the sender. Read receipts do not involve any cryptography or encrypted message payload. 

_Note that clients should send a read receipt message only when decryption has succeeded on an incoming message, and the incoming message is not itself a read receipt!_

The JSON `message` structure is described under "Message upload". To send a read receipt, fill in the JSON `message` structure so that `payload` is empty, and the field `receiptID` contains the `id` field of the message you wish to acknowledge.

### Encrypting attachments

JMessage clients can also send attachments (files) as follows. To send an attachment, the sending client performs the following steps:

1. First, it selects a random 256-bit ChaCha20 key `KEY`.
2. Next it encrypts the file using ChaCha20 under key `KEY` with a zero IV.
3. It computes `H = SHA256(encrypted file)`.
4. It uploads the encrypted file to the JMessage server, and obtains a temporary URL.
5. It sends a standard encrypted message containing `url, KEY, H` in the following structured plaintext:

```
>>>MSGURL=<url>?KEY=<KEY>?H=<H>
```

### Decrypting attachments

When a client receives and decrypts a message that contains a string matching the form specified above, it parses to obtain `url, KEY, H` and:

1. Downloads the file from the given URL.
2. Computes `HASH = SHA256(encrypted file)` and verifies that this matches the hash `H` specified in the message. If not, it rejects the attachment.
3. Decrypts the message using the key `KEY` using ChaCha20 with IV=0.

If all steps are successful, the client should indicate to the user that the file has been received and written to disk.

### Computing key fingerprints

A client may compute a key fingerprint of any user. This is computed by first downloading the user's public key `EncPK, SigPK` and then computing:

```
F = Truncate(SHA256(EncPK || SigPK), 10)
```

Here `Truncate(X, 10)` outputs the first (most significant) 10 bytes of the string and discards the rest. The key fingerprint should be encoded in hexadecimal notation as in the following example:

```
93 AF 70 ED 10 00 82 91 02 74
```
