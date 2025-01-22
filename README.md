# Secure Messaging System Documentation

This document provides an overview of the secure messaging system, describing how the server and clients communicate, the data formats used, cryptographic measures applied, and how the system achieves its security goals.

---

## Communication Overview

### Client-Server Interaction Workflow

#### SSL Handshake

- When a client connects to the server, an SSL handshake is performed to establish a secure encrypted channel.
- **Relevant Code**:
  - Client: `client.c` (`ssl_handshake`)
  - Server: `server.c` (`ssl_handshake`)

#### Server Workflow

- The server receives encrypted messages through SSL, decrypts them, and processes them.
- **Validation Checks**:
  - Command formatting
  - User authentication
  - Recipient availability (for private messages)

#### Message Storage and Notifications

- **Public Messages**: Stored as plaintext in the database.
- **Private Messages**: Encrypted using AES-256-CBC with a random IV and stored in the database.
- The server notifies clients when a message is sent, decrypting private messages before forwarding them securely.

---

## Commands and Messages

### Command Formats

| Command           | Format                            | Description                |
| ----------------- | --------------------------------- | -------------------------- |
| Register          | `/register <username> <password>` | Registers a new user.      |
| Login             | `/login <username> <password>`    | Logs in a user.            |
| List Online Users | `/users`                          | Lists all logged-in users. |
| Public Message    | `<message>`                       | Sends a public message.    |
| Private Message   | `@<username> <message>`           | Sends a private message.   |
| Exit              | `/exit`                           | Closes the client session. |
- Invalid commands return an error.
---

## Cryptographic Measures

### 1. SSL/TLS Encryption

- Ensures all communication between clients and the server is encrypted.
- **Protection Against**:
  - Eavesdropping
  - Man-in-the-middle attacks

### 2. Private Message Encryption

- Private messages are encrypted with AES-256-CBC using a randomly generated IV.
- The IV is stored alongside the ciphertext in the database.
- **Relevant Code**:
  - Encryption: `encrypt_message` in `crypto.c`
  - Decryption: `decrypt_message` in `crypto.c`

### 2.1 E2EE For Private Messages (not implemented due to lack of time)

- Each user generates then sends their own public key to the server upon registering. The server stores the public keys of the users in the database.
- Private messages are encrypted with the public key of the recipient on the sender's side and decrypted with the private key of the recipient on the receiving end.
- If the user does not have the public key of the recipient, they request it from the server using `/pubkey <username>`. The server then responds with the public key and the user stores the public key locally.

### 3. Password Hashing

- Passwords are hashed with SHA-256 before storage in the database.
- During login, the hash of the provided password is compared with the stored hash.
- **Relevant Code**:
  - Hashing: `hash_password` in `crypto.c`

---

## Database Design

- The system uses SQLite for message and user data storage.
- **Relevant Code**: `database.c`

### Tables

#### Users Table

- `user_id`: Username (Key)
- `password`: Hashed password

#### Messages Table

- `id`: Message ID (Primary Key)
- `sender_id`: Sender's User ID
- `recipient_id`: Recipient's User ID (NULL for public messages)
- `content`: Message content (encrypted for private messages)
- `is_encrypted`: Indicates if the message is private
- `iv`: IV used for encryption (only for private messages)
- `timestamp`: Time the message was sent

---

## Security Goals and Defenses

### Secure Network

- **Attack Mitigated**: Eavesdropping on communication.
- **Defense**: SSL/TLS encrypts communication between the client and the server.

### Secure Password Storage

- **Attack Mitigated**: Password disclosure due to database leaks.
- **Defense**: Passwords are hashed before storage.

### Command Validation

- **Attack Mitigated**: Command injection and misuse.
- **Defense**: Server validates all commands for proper formatting and user state.

---

## File and Function References

| Functionality       | File         | Functions                                                        |
| ------------------- | ------------ | ---------------------------------------------------------------- |
| SSL Handshake       | `server.c`   | `ssl_handshake`                                                  |
| Command Parsing     | `worker.c`   | `execute_request`                                                |
| Encrypting Messages | `crypto.c`   | `encrypt_message`                                                |
| Decrypting Messages | `crypto.c`   | `decrypt_message`                                                |
| Password Hashing    | `crypto.c`   | `hash_password`                                                  |
| Database Operations | `database.c` | `get_message`, `insert_public_message`, `insert_private_message` |

---

## Security Properties and Protocol Countermeasures

### 1. Confidentiality and Integrity of Private Messages

- **Requirement**: Mallory must not access or alter private messages.
- **Countermeasures**:
  - **Encryption**: Private messages (`PRIVMSG`) are stored encrypted by the server. Even if Mallory intercepts the message, they cannot decrypt it thanks to ssl.

### 2. Authentication and Prevention of Impersonation

- **Requirement**: Mallory must not impersonate users or send messages on their behalf.
- **Countermeasures**:
  - **Auth requirement**: Sending messages requires the user to be logged in. The log in information is stored on the worker therefore providing a wrong uid, or user token for the message is not a possibility. The uid is attached to the message on the server side, preventing attackers to provide a fake sender id.

### 3. Password and Key Protection

- **Requirement**: Mallory must not discover users' passwords, private keys, or private messages.
- **Countermeasures**:
  - **Secure Storage**: The server stores only the hashed passwords. The private messages are encrypted, which prevents sensitive messages to be leaked. No user keys is stored on the server.

### 4. Server and Client Isolation from System Privileges

- **Requirement**: Mallory must not use the software to access or modify unauthorized files or settings.
- **Countermeasures**:
  - **File System Restrictions**: The server and client are limited to modifying specific directories (`chat.db`, `clientkeys`). No access is granted to other files or system settings, safeguarding against privilege escalation.
  - **Controlled Error Handling**: The server and client are designed to handle errors gracefully, reducing the likelihood of crashes or unintentional data leakage.

### 5. Cryptographic Handling and Secure Session Establishment

- **Requirement**: Messages must be protected against tampering and eavesdropping.
- **Countermeasures**:
  - **SSL Secure Channel**: Before message transmission, a secure SSL connection is established with OpenSSL, ensuring that data exchanged between client and server is encrypted, preventing eavesdropping and injection attacks.

### 6. User Protection from Malicious Servers

- **Requirement**: If Mallory operates a malicious server, it should not compromise client security.
- **Countermeasures**: (not implemented)
	- **Server Certificate Validation** 
		- Clients verify the server's identity using an X.509 certificate issued by a trusted Certificate Authority (CA). 
		- The client ensures the certificate is valid, matches the server hostname, and is not expired or revoked. 

### 7. Confidentiality of User Lists

- **Requirement**: User lists should only be accessible to authenticated users.
- **Countermeasures**:
  - **Token Verification for `/users` Command**: Only authenticated clients can access the list of online users. This prevents Mallory from accessing the list of users without proper authentication.

## Limitations and Notes

### Denial of Service (DoS)

- While the system includes error handling, specific mitigations for DoS are not implemented.

### End-to-End Encryption Between Users

- While messages between the server and client are encrypted, the server can still read the message and then send another encrypted message to the client.

- We were trying to implement using private and public keys for the client. The idea we had is that when a client registers, the public key of the client is also sent and saved in the database, and when we send a private message, the sender would request the public key of the recipient, then encrypt it and send the encrypted message. Then the recepient would decrypt it. Even though that was our idea, we were not able to implement it in code

### Salted hashes

- Protects against rainbow table attacks, which leverage precomputed hash tables to crack passwords.
- By adding a unique salt to each password before hashing, it ensures that even if two users have the same password, their hashes will differ. This makes cracking individual passwords much harder.

### Server validation

- Prevents man-in-the-middle (MITM) attacks, where an attacker intercepts and manipulates communication by impersonating the server.
- Guarantees that clients are communicating with the legitimate server, ensuring the integrity and confidentiality of data exchanged.`