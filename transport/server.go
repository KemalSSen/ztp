package transport

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"ztp/crypto"
	"ztp/identity"
	"ztp/protocol"
)

// Allowed roles that can access the server
var allowedRoles = map[string]bool{
	"admin": true,
	"user":  true,
}

// Global session store
var sessions = NewSessionManager()

// StartServer launches the ZTP server
func StartServer(address string) error {
	sessions.StartCleanup(5 * time.Second)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	log.Printf("[ZTP] Server listening on %s", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ZTP] Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

// handleConnection manages a new client session
func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// --- Phase 1: Key Exchange ---
	serverKeys, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Printf("[ZTP] Key generation failed: %v", err)
		return
	}

	clientPub := make([]byte, 32)
	if _, err := io.ReadFull(r, clientPub); err != nil {
		log.Printf("[ZTP] Failed to read client public key: %v", err)
		return
	}
	clientPubKey, err := crypto.DecodePublicKey(clientPub)
	if err != nil {
		log.Printf("[ZTP] Invalid client public key: %v", err)
		return
	}

	if _, err := w.Write(serverKeys.Public[:]); err != nil {
		log.Printf("[ZTP] Failed to send server public key: %v", err)
		return
	}
	w.Flush()

	sharedKey, err := crypto.ComputeSharedKey(serverKeys.Private, clientPubKey)
	if err != nil {
		log.Printf("[ZTP] Shared key computation failed: %v", err)
		return
	}
	sessionKey := crypto.DeriveSessionKey(sharedKey, []byte("ztp-handshake"))
	log.Printf("[DEBUG] Session Key: %x", sessionKey)

	// --- Phase 2: Authentication ---
	authFrame, err := protocol.Decode(r)
	if err != nil {
		log.Printf("[ZTP] Failed to read auth frame: %v", err)
		return
	}
	if authFrame.Type != protocol.TypeHandshakeInit {
		log.Println("[ZTP] Expected handshake token first, rejecting.")
		return
	}
	tokenPlain, err := crypto.Decrypt(sessionKey, authFrame.Nonce, authFrame.Payload, nil)
	if err != nil {
		log.Printf("[ZTP] Token decryption failed: %v", err)
		return
	}
	claims, err := identity.VerifyToken(string(tokenPlain))
	if err != nil {
		log.Printf("[ZTP] Invalid token: %v", err)
		return
	}
	if !allowedRoles[claims.Role] {
		log.Printf("[ZTP] Access denied for client: %s with role %s", claims.ClientID, claims.Role)
		return
	}
	log.Printf("[ZTP] Authenticated client: %s with role: %s", claims.ClientID, claims.Role)
	log.Println("[ZTP] Handshake complete. Secure session established.")
	// Save client identity
	sessions.SaveWriter(claims.ClientID, w)
	// Save session for resume
	sessions.Save(claims.ClientID, Session{
		Key:      sessionKey,
		Role:     claims.Role,
		LastSeen: time.Now(),
	})

	// --- Phase 3: Stream Routing ---
	router := NewStreamRouter(sessionKey, w)
	router.roles[1] = claims.Role // attach role to control stream

	for {
		frame, err := protocol.Decode(r)
		if err != nil {
			if err == io.EOF {
				log.Println("[ZTP] Connection closed by client.")
			} else {
				log.Printf("[ZTP] Frame decode error: %v", err)
			}
			router.CloseAll()
			return
		}
		router.Dispatch(frame)
	}
}
