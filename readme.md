# Zero Trust Protocol (ZTP)

## Version
- 1.0 (Initial Draft)

## Overview
ZTP (Zero Trust Protocol) is a lightweight, encrypted, authenticated, stream-multiplexed protocol designed for secure client-server communication over untrusted networks. It leverages modern cryptography and token-based identity verification.

---

## Frame Format
Each frame is transmitted over the connection as a sequence of bytes with the following structure:

| Field       | Size (bytes) | Description                                |
|:------------|:------------|:-------------------------------------------|
| Version     | 2            | Protocol version number                   |
| Type        | 2            | Frame type (handshake, data, etc.)         |
| StreamID    | 4            | Logical stream identifier                 |
| Nonce       | 12           | Unique nonce for encryption               |
| Length      | 4            | Length of the encrypted payload           |
| Payload     | Variable     | Encrypted application or control data     |

**Total Header Size:** 24 bytes.

---

## Message Types
- **0x01 - TypeHandshakeInit**: Client sends encrypted token after handshake.
- **0x02 - TypeHandshakeAck**: (Optional) Server acknowledgment.
- **0x03 - TypeData**: Regular encrypted application or control message.
- **0x04 - TypeClose**: Closing connection or stream.

---

## Handshake Flow

1. **Key Exchange**:
   - Client and Server exchange Curve25519 public keys.
   - Each derives a shared secret.

2. **Session Key Derivation**:
   - Shared secret passed through SHA-256 to derive the session encryption key.

3. **Token Transmission**:
   - Client encrypts a signed identity token (HMAC-SHA256) using the session key.
   - Token includes:
     - ClientID
     - Role
     - Expiration Time

4. **Token Verification**:
   - Server decrypts and verifies token signature and expiration.
   - Server enforces access based on declared role.

5. **Secure Session Established**.

---

## Stream Multiplexing
- Multiple logical streams can exist simultaneously over one TCP connection.
- Stream IDs must be positive integers.
- Example assignments:
  - Stream ID `1` -> Chat messages.
  - Stream ID `2` -> Control commands (ping, status, etc.).

---

## Encryption Details
- **Cipher**: ChaCha20-Poly1305 (AEAD)
- **Nonce Size**: 12 bytes (unique per message)
- **Key Size**: 32 bytes (derived session key)
- **Payload Integrity**: Verified by Poly1305 tag

---

## Security Guarantees
- Confidentiality: All payloads are encrypted.
- Integrity: AEAD ensures tamper detection.
- Authentication: Clients authenticate via signed tokens.
- Authorization: Enforced by role-based token verification.
- Replay Protection (Coming Soon): Unique nonces per message prevent replays.

---

## Future Extensions
- Session Resumption
- Heartbeat Frames
- Stream Priority
- Compression
- Advanced Replay Protection (Anti-Replay Window)

---

# End of Spec
---

✨ Drafted April 2025 - ZTP Core Team

**************************************************************New************************************************************************



Zero Trust Protocol (ZTP) 🚀
A lightweight, encrypted, authenticated, stream-multiplexed secure protocol written in Go.

✨ Features
🔒 End-to-end encryption using Curve25519 (key exchange) and ChaCha20-Poly1305 (message encryption).

🧩 Multiple logical streams over a single TCP connection (Control and Chat streams).

🔐 Identity verification with signed tokens (JWT-based).

📂 Secure file upload and download support.

📡 Idle stream timeout and automatic cleanup.

🛡️ Minimal, battle-ready, Zero Trust design principles.

🧹 Full logging and graceful error handling.

📁 Project Structure
bash
Copy
Edit
ztp/
├── cmd/
│   ├── client/       # Client main app (go run ./cmd/client)
│   └── server/       # Server main app (go run ./cmd/server)
├── crypto/           # Crypto: encryption, key exchange, session keys
├── identity/         # Token creation and verification
├── protocol/         # Framing: custom binary frame format
├── transport/        # StreamRouter, UploadManager, main transport logic
└── server_files/     # Server-side folder for uploaded/downloaded files
🚀 Quick Start
1. Start the Server
bash
Copy
Edit
go run ./cmd/server
Server listens on :9999 by default.

2. Start the Client
bash
Copy
Edit
go run ./cmd/client
You'll be connected securely and ready to type commands.

3. Available Commands

Command	Description
ping	Pings the server
status	Checks server status
time	Gets server UTC time
list	Lists available files (simulated)
info	Shows ZTP server info
echo <message>	Echoes back the message
upload <filename>	Uploads a file to server
download <filename>	Downloads a file from server
exit	Disconnects client
🛠 Technology Stack
Language: Go 1.20+

Crypto: Curve25519, ChaCha20-Poly1305

Multiplexing: Custom logical streams

Framing: Custom lightweight binary protocol

📜 Example Session
bash
Copy
Edit
$ go run ./cmd/client

>> Connected! Type commands (ping, status, time, upload file.txt, download file.txt, etc.)
>> Type 'exit' to quit.

> ping
[Server Reply]: pong

> upload myfile.txt
[Client] Upload complete!

> download myfile.txt
[Client] Downloaded 'myfile.txt' successfully

> exit
[Client] Exiting...
📚 Protocol Flow (Simplified)
plaintext
Copy
Edit
Client                          Server
  |                                |
  |--- Ephemeral Public Key -----> |
  |                                |
  |<--- Ephemeral Public Key ----- |
  |                                |
  |--- Encrypted Identity Token -->|
  |                                |
  |<--- Session Established ------ |
  |                                |
  |--- Data Frames (Control/Chat) ->|
  |<--- Response Frames -----------|
🔥 Status
✅ Fully operational MVP ready for expansion.
✅ Secure, extensible, clean Go codebase.