# Zero Trust Protocol (ZTP)

## Overview

ZTP (Zero Trust Protocol) is a secure, encrypted, and authenticated transport protocol designed to operate over untrusted networks. It uses modern cryptographic primitives, a stream-multiplexed architecture, and token-based identity verification to ensure confidentiality, integrity, and access control.

---

## ✨ Key Features

### 🔐 Security

* **Encryption**: End-to-end encryption using ChaCha20-Poly1305 AEAD.
* **Authentication**: Client identity verified using signed HMAC-SHA256 tokens.
* **Replay Protection**: Each message includes a unique nonce.
* **Tamper Detection**: Poly1305 ensures integrity and authenticity.

### 🧩 Modular Design

* Supports multiple **logical streams** over a single TCP connection.
* Control and application traffic separated via **stream IDs**.
* Upload/download with resumable support via server-managed offsets.

### 🛠️ Developer Friendly

* Easy-to-use CLI and client library.
* Fully extendable and modular backend.
* Detailed debug and logging output.

### 📈 Metrics & Observability

* Tracks per-stream: message count, inbound/outbound bytes, decrypt failures.
* Cleaned up on stream close or timeout.

---

## 🧪 Current Functionality

### ✅ Secure Handshake

1. ECDH Key Exchange (Curve25519)
2. Derive 32-byte session key via SHA-256
3. Encrypted identity token from client to server
4. Role verification and session start

### ✅ Frame Format

| Field    | Size (bytes) | Description              |
| -------- | ------------ | ------------------------ |
| Version  | 2            | Protocol version         |
| Type     | 2            | Frame type               |
| StreamID | 4            | Logical stream ID        |
| Nonce    | 12           | Encryption nonce         |
| Length   | 4            | Encrypted payload length |
| Payload  | Variable     | AEAD-encrypted data      |

### ✅ Message Types

* `0x01` - HandshakeInit
* `0x02` - HandshakeAck (planned)
* `0x03` - Encrypted Data
* `0x04` - Stream/Connection Close

### ✅ Streams

* `1` - Chat messages
* `2` - Control commands (e.g. ping, time, echo)
* `N` - Arbitrary, per-client streams (file transfers, uploads, etc.)

### ✅ Supported Commands

| Command    | Description                     |
| ---------- | ------------------------------- |
| `ping`     | Server replies with `pong`      |
| `status`   | Shows server status             |
| `time`     | Returns current UTC time        |
| `info`     | Returns server description      |
| `echo`     | Echoes back the user message    |
| `list`     | Lists available files           |
| `upload`   | Upload a file to the server     |
| `download` | Download a file from the server |

### ✅ Uploads

* Streamed over Stream ID `2`
* Server saves to `server_files/<filename>`
* Supports resumable uploads via file offset

### ✅ Downloads

* Server reads file and streams back in 1024B chunks
* Ends with `[EOF]` marker
* Saved as `downloaded_<filename>` on client

### ✅ CLI Client

Usage:

```bash
ztp-client --addr <host:port> <command> [args]
```

Examples:

```bash
ztp-client --addr localhost:9999 ping
ztp-client --addr localhost:9999 upload notes.txt
ztp-client --addr localhost:9999 download notes.txt
ztp-client --addr localhost:9999 chat "hello world"
```

---

## 📁 Project Structure

```
ztp/
├── cmd/                  # Entry points
│   ├── client/           # CLI client
│   └── server/           # Main server
├── transport/            # Core transport logic
│   ├── server.go
│   ├── client.go
│   ├── stream_router.go
│   └── upload_handler.go
├── crypto/               # Key exchange, encryption
├── identity/             # Token creation/verification
├── protocol/             # Frame structs + constants
├── server_files/         # Uploaded files stored here
```

---

## 🔮 Upcoming Features

### 🧠 Session Resumption

* Cache client key/session ID for re-auth without full handshake

### ❤️ Heartbeat Frames

* Keep-alive pings every N seconds
* Auto-close dead connections

### 📊 Stream Priority & QoS

* Assign weights to streams (e.g., control > chat > file)
* Fair scheduling in congested conditions

### 🔁 Advanced Replay Protection

* Implement anti-replay sliding window
* Detect reordered or replayed frames

### 📦 Compression Support

* Compress chat/file payloads (GZIP, Snappy)

### 🌐 Multi-client Support

* Serve multiple clients concurrently
* Authenticate and manage client roles per connection

---

## 🧠 Design Goals

* **Simplicity**: clear frame format, single entrypoint
* **Security-first**: crypto defaults, nonce checks
* **Extensibility**: plug-and-play stream logic
* **Minimal Dependencies**: Go stdlib + crypto

---

## 🚀 Getting Started

### Build CLI and Server

```bash
cd ztp
go build -o ztp-client ./cmd/client
go build -o ztp-server ./cmd/server
```

### Start Server

```bash
./ztp-server
```

### Start Client

```bash
./ztp-client --addr localhost:9999 ping
```

---

## 👨‍💻 Authors

Built with 🧠 by the ZTP Core Team. Drafted April 2025.

---

## 📜 License

MIT © 2025
