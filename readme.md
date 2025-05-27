# ZTP (Zero Trust Protocol) - Secure TCP Communication Framework

## ✨ Overview

ZTP is a custom-designed, secure communication protocol built over TCP, using modern cryptographic primitives (X25519, ChaCha20-Poly1305, HMAC) to ensure confidentiality, integrity, and authentication in peer-to-peer or client-server models. It features encrypted file transfers, distributed role-based messaging, streaming upload/download support, replay-attack mitigation, and extensible modular design.

---

## 📁 Project Structure

```
ztp/
├── cmd/               # CLI entry points for client & server
│   ├── ztp-client/
│   └── ztp-server/
├── crypto/            # X25519 key exchange, ChaCha20 encryption, HMAC
├── identity/          # JWT-based role authentication
├── protocol/          # Frame encoding/decoding & constants
├── transport/         # StreamRouter, UploadManager, and communication logic
├── server_files/      # Directory for uploaded files
├── go.mod
└── README.md
```

---

## 🌐 Protocol Design

### ▶ Frame Structure

Each encrypted message sent between client and server is wrapped in a custom frame:

| Field      | Size (Bytes) | Description                           |
| ---------- | ------------ | ------------------------------------- |
| StreamID   | 4            | Identifier for logical communication  |
| FrameType  | 1            | Type (Handshake, Data, Control, etc.) |
| Nonce      | 12           | Random nonce for AEAD encryption      |
| PayloadLen | 4            | Length of encrypted payload           |
| Payload    | Variable     | ChaCha20-Poly1305 encrypted data      |

* **FrameType** enum:

  * `TypeHandshakeInit = 0x01`
  * `TypeData = 0x02`
  * `TypeAck = 0x03`

### Nonce Usage

Each frame includes a unique 96-bit nonce generated using `crypto/rand`. Nonce ensures semantic security for AEAD and prevents replay attacks. All previously used nonces are cached and checked server-side (via `ReplayBuffer`).

---

## 🔐 Cryptography

* **Key Exchange**: X25519 (Elliptic Curve Diffie-Hellman)
* **Session Encryption**: ChaCha20-Poly1305 AEAD
* **Integrity**: AEAD internal + optional HMAC
* **Token Authentication**: JWT (ES256)

Session key is derived via `HKDF(shared_secret, "ztp-handshake")`.

---

## 🎓 Authentication & Roles

* Client generates JWT via `identity.CreateToken(clientID, role)`
* JWT is encrypted and sent in the handshake frame
* Server verifies signature and extracts `clientID`, `role`

Roles can be used to restrict features (e.g. download-only, admin, etc.)

---

## 🚀 Core Components

### Client Logic (StartClient)

* Performs key exchange and handshake
* Authenticates via token
* Parses user input and dispatches commands
* Handles uploads/downloads, chats, control commands

### Server Logic (StreamRouter)

* Receives and decrypts frames
* Determines stream type (control/chat/upload)
* Starts `UploadManager` or command handler based on priority
* Sends response frames with encrypted data

---

## 📄 Upload Workflow

1. Client sends: `upload notes.txt`
2. Server responds: `Ready to receive file at offset X`
3. Client streams encrypted file chunks
4. Server writes chunks using `UploadManager`
5. Client sends `UploadEndMarker`
6. Server finalizes and acknowledges

### GZIP Support

* If user sends `upload --gzip notes.txt`, the file is compressed on-the-fly using `gzip.NewWriter` and streamed through `io.Pipe`.

---

## 📥 Download Workflow

1. Client sends: `download file.txt`
2. Server reads the file
3. Splits into encrypted chunks
4. Sends chunks in multiple frames
5. Appends `UploadEndMarker`

---

## ⚖️ Security Features

| Feature                   | Mechanism                     |
| ------------------------- | ----------------------------- |
| Confidentiality           | ChaCha20-Poly1305 AEAD        |
| Authentication            | JWT with ECDSA (ES256)        |
| Replay protection         | Nonce tracking (ReplayBuffer) |
| Stream isolation          | Unique StreamIDs              |
| Session hijack prevention | Key-pair per session          |
| Role-based access         | Claims in JWT token           |

---

## ⚙️ Build & Run

```bash
# Server
cd cmd/ztp-server
go run main.go

# Client
cd cmd/ztp-client
go run main.go --id your-client-id
```

---

## 🚫 Known Limitations

* No full retransmission logic for dropped frames
* Private chat is partially implemented (broadcast works)
* No certificate authority or mutual auth yet
* No persistent storage or database

---

## 🌐 Future Work

* Private message ACK + retries
* WebSocket or HTTP-over-ZTP tunnel
* REST API for admin control
* GUI frontend with React
* TLS-like certificate validation
* More granular role permissions

---

## 📅 Contributors

* Kemal Ş.
* Ismail Serin


---

## ⚠️ Disclaimer

This project is for educational purposes only. It is not recommended for use in production without a thorough security audit.

---


## 🧵 License

MIT License
