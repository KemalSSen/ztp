package transport

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"ztp/crypto"
	"ztp/identity"
	"ztp/protocol"
)

func StartClient(address string) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// Phase 1: Key Exchange
	clientKeys, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	if _, err := w.Write(clientKeys.Public[:]); err != nil {
		return fmt.Errorf("failed to send public key: %w", err)
	}
	w.Flush()

	serverPub := make([]byte, 32)
	if _, err := r.Read(serverPub); err != nil {
		return fmt.Errorf("failed to read server public key: %w", err)
	}
	serverPubKey, err := crypto.DecodePublicKey(serverPub)
	if err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	sharedKey, err := crypto.ComputeSharedKey(clientKeys.Private, serverPubKey)
	if err != nil {
		return fmt.Errorf("shared key computation failed: %w", err)
	}
	sessionKey := crypto.DeriveSessionKey(sharedKey, []byte("ztp-handshake"))
	log.Printf("[DEBUG] Session Key: %x", sessionKey)

	// Phase 2: Authentication
	token, err := identity.CreateToken("kemal-client", "admin", 5*time.Minute)
	if err != nil {
		return fmt.Errorf("token creation failed: %w", err)
	}
	tokenNonce, _ := crypto.GenerateNonce()
	tokenCipher, _ := crypto.Encrypt(sessionKey, tokenNonce, []byte(token), nil)
	tokenFrame, _ := protocol.NewFrameWithStream(1, protocol.TypeHandshakeInit, tokenNonce, tokenCipher)
	tokenBytes, _ := tokenFrame.Encode()
	w.Write(tokenBytes)
	w.Flush()

	// Phase 3: Interactive session
	console := bufio.NewReader(os.Stdin)
	fmt.Println(">> Connected! Type commands (ping, status, time, upload file.txt, download file.txt, etc.)")
	fmt.Println(">> Type 'exit' to quit.")

	for {
		fmt.Print("> ")
		input, _ := console.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}
		if strings.ToLower(input) == "exit" {
			log.Println("[Client] Exiting...")
			break
		}

		lower := strings.ToLower(input)
		if strings.HasPrefix(lower, "upload ") {
			handleUpload(w, sessionKey, input)
			continue
		}

		streamID := uint32(2) // Control stream by default
		nonce, _ := crypto.GenerateNonce()
		ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(input), nil)
		frame, _ := protocol.NewFrameWithStream(streamID, protocol.TypeData, nonce, ciphertext)
		frameBytes, _ := frame.Encode()
		w.Write(frameBytes)
		w.Flush()

		log.Printf("[Client] Sent command '%s' on Stream %d", input, streamID)

		// Wait for server reply
		responseFrame, err := protocol.Decode(r)
		if err != nil {
			if err == io.EOF {
				log.Println("[Client] Server closed connection.")
				break
			}
			return fmt.Errorf("failed to decode server frame: %w", err)
		}
		response, _ := crypto.Decrypt(sessionKey, responseFrame.Nonce, responseFrame.Payload, nil)
		fmt.Printf("[Server Reply]: %s\n", string(response))
	}
	return nil
}

func handleUpload(w *bufio.Writer, sessionKey [32]byte, command string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		fmt.Println("[Client] Usage: upload <filename>")
		return
	}
	filename := parts[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[Client] Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	// Step 1: Notify server
	nonce, _ := crypto.GenerateNonce()
	ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(command), nil)
	frame, _ := protocol.NewFrameWithStream(2, protocol.TypeData, nonce, ciphertext)
	frameBytes, _ := frame.Encode()
	w.Write(frameBytes)
	w.Flush()

	time.Sleep(300 * time.Millisecond)

	// Step 2: Send file content
	buffer := make([]byte, 1024)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			fmt.Printf("[Client] Failed to read file: %v\n", err)
			return
		}
		if n == 0 {
			break
		}
		nonce, _ := crypto.GenerateNonce()
		ciphertext, _ := crypto.Encrypt(sessionKey, nonce, buffer[:n], nil)
		frame, _ := protocol.NewFrameWithStream(2, protocol.TypeData, nonce, ciphertext)
		frameBytes, _ := frame.Encode()
		w.Write(frameBytes)
		w.Flush()
	}

	// Step 3: Signal end of file
	nonce, _ = crypto.GenerateNonce()
	ciphertext, _ = crypto.Encrypt(sessionKey, nonce, []byte(protocol.UploadEndMarker), nil)
	frame, _ = protocol.NewFrameWithStream(2, protocol.TypeData, nonce, ciphertext)
	frameBytes, _ = frame.Encode()
	w.Write(frameBytes)
	w.Flush()

	fmt.Println("[Client] Upload complete!")
}
