package transport

import (
	"bufio"
	"compress/gzip"
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

func StartClient(address string, clientID string) error {
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
	token, err := identity.CreateToken(clientID, "admin", 5*time.Minute)
	if err != nil {
		return fmt.Errorf("token creation failed: %w", err)
	}
	tokenNonce, _ := crypto.GenerateNonce()
	tokenCipher, _ := crypto.Encrypt(sessionKey, tokenNonce, []byte(token), nil)
	tokenFrame, _ := protocol.NewFrameWithStream(1, protocol.TypeHandshakeInit, tokenNonce, tokenCipher)
	tokenBytes, _ := tokenFrame.Encode()
	w.Write(tokenBytes)
	w.Flush()

	// 🔁 Frame Routing Setup
	controlChan := make(chan *protocol.Frame, 10)
	chatChan := make(chan *protocol.Frame, 10)

	go routerReader(r, controlChan, chatChan) // centralized frame reader
	go listenForChats(chatChan, sessionKey)   // async chat listener

	console := bufio.NewReader(os.Stdin)
	fmt.Println(">> Connected! Type commands (ping, status, time, upload file.txt, download file.txt, etc.)")
	fmt.Println(">> Type 'exit' to quit.")

	for {
		fmt.Print("> ")
		input, _ := console.ReadString('\n')
		input = strings.TrimSpace(input)
		input = strings.TrimPrefix(input, "> ")
		if input == "" {
			continue
		}
		if strings.ToLower(input) == "exit" {
			log.Println("[Client] Exiting...")
			break
		}

		lower := strings.ToLower(input)
		cmdWord := strings.SplitN(lower, " ", 2)[0]

		controlCommands := map[string]bool{
			"ping":     true,
			"status":   true,
			"time":     true,
			"info":     true,
			"list":     true,
			"chatlist": true,
		}

		if controlCommands[cmdWord] {
			streamID := uint32(2)
			nonce, _ := crypto.GenerateNonce()
			ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(input), nil)
			frame, _ := protocol.NewFrameWithStream(streamID, protocol.TypeData, nonce, ciphertext)
			frameBytes, _ := frame.Encode()
			w.Write(frameBytes)
			w.Flush()

			// 📨 Wait for reply on control stream
			responseFrame := <-controlChan
			plain, _ := crypto.Decrypt(sessionKey, responseFrame.Nonce, responseFrame.Payload, nil)
			fmt.Printf("[Server Reply]: %s\n", string(plain))
			continue
		}

		if strings.HasPrefix(lower, "chat @") {
			sendPrivateMessageWithRetry(w, controlChan, sessionKey, input)

			continue
		}

		if strings.HasPrefix(lower, "upload ") {
			handleUpload(r, w, sessionKey, input)
			continue
		}

		if strings.HasPrefix(lower, "download ") {
			handleDownload(r, w, sessionKey, input)
			continue
		}

		// Default broadcast chat or unknown command
		streamID := uint32(2)
		nonce, _ := crypto.GenerateNonce()
		ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(input), nil)
		frame, _ := protocol.NewFrameWithStream(streamID, protocol.TypeData, nonce, ciphertext)
		frameBytes, _ := frame.Encode()
		w.Write(frameBytes)
		w.Flush()

		log.Printf("[Client] Sent command '%s' on Stream %d", input, streamID)

		responseFrame := <-controlChan
		response, _ := crypto.Decrypt(sessionKey, responseFrame.Nonce, responseFrame.Payload, nil)
		fmt.Printf("[Server Reply]: %s\n", string(response))
	}

	return nil
}

func routerReader(r *bufio.Reader, controlChan, chatChan chan *protocol.Frame) {
	for {
		frame, err := protocol.Decode(r)
		if err != nil {
			log.Printf("[Router] Error decoding frame: %v", err)
			continue
		}
		switch frame.StreamID {
		case 2:
			controlChan <- frame
		case 3:
			chatChan <- frame
		default:
			log.Printf("[Router] Unknown stream ID: %d", frame.StreamID)
		}
	}
}

func sendPrivateMessageWithRetry(w *bufio.Writer, controlChan chan *protocol.Frame, sessionKey [32]byte, input string) {
	streamID := uint32(2) // kontrol kanalı

	nonce, _ := crypto.GenerateNonce()
	ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(input), nil)
	frame, _ := protocol.NewFrameWithStream(streamID, protocol.TypeData, nonce, ciphertext)
	frameBytes, _ := frame.Encode()
	w.Write(frameBytes)
	w.Flush()

	// Beklenen cevap controlChan üzerinden geliyor
	responseFrame := <-controlChan
	plain, _ := crypto.Decrypt(sessionKey, responseFrame.Nonce, responseFrame.Payload, nil)
	fmt.Printf("[Server Reply]: %s\n", string(plain))
}

/*func startHeartbeat(w *bufio.Writer, sessionKey [32]byte) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nonce, _ := crypto.GenerateNonce()
		payload, _ := crypto.Encrypt(sessionKey, nonce, []byte("ping"), nil)
		frame, _ := protocol.NewFrameWithStream(2, protocol.TypeData, nonce, payload)
		frameBytes, _ := frame.Encode()
		w.Write(frameBytes)
		w.Flush()
		log.Println("[Heartbeat] Sent ping")
	}
}*/

func listenForChats(chatChan chan *protocol.Frame, sessionKey [32]byte) {
	for frame := range chatChan {
		msg, err := crypto.Decrypt(sessionKey, frame.Nonce, frame.Payload, nil)
		if err != nil {
			log.Printf("[Chat] Decryption failed: %v", err)
			continue
		}
		fmt.Printf("\n[Chat] %s\n> ", string(msg))
	}
}

func handleUpload(r *bufio.Reader, w *bufio.Writer, sessionKey [32]byte, command string) {
	useGzip := false
	var filename string
	var serverCommand string

	// Komutu parçala: örnekler -> upload test.txt, upload --gzip test.txt, upload-gzip test.txt
	parts := strings.Fields(command)
	if len(parts) < 2 {
		fmt.Println("[Client] Usage: upload <filename> | upload --gzip <filename> | upload-gzip <filename>")
		return
	}

	switch parts[0] {
	case "upload":
		if len(parts) == 3 && parts[1] == "--gzip" {
			useGzip = true
			filename = parts[2]
			serverCommand = "upload-gzip " + filename
		} else if len(parts) == 2 {
			filename = parts[1]
			serverCommand = "upload " + filename
		} else {
			fmt.Println("[Client] Invalid upload syntax.")
			return
		}
	case "upload-gzip":
		if len(parts) == 2 {
			useGzip = true
			filename = parts[1]
			serverCommand = "upload-gzip " + filename
		} else {
			fmt.Println("[Client] Invalid upload-gzip syntax.")
			return
		}
	default:
		fmt.Println("[Client] Unknown upload command.")
		return
	}

	// Step 1: Send command to server
	nonce, _ := crypto.GenerateNonce()
	ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(serverCommand), nil)
	frame, _ := protocol.NewFrameWithStream(2, protocol.TypeData, nonce, ciphertext)
	frameBytes, _ := frame.Encode()
	w.Write(frameBytes)
	w.Flush()

	// Step 2: Await server response
	responseFrame, err := protocol.Decode(r)
	if err != nil {
		fmt.Printf("[Client] Failed to read server response: %v\n", err)
		return
	}
	response, _ := crypto.Decrypt(sessionKey, responseFrame.Nonce, responseFrame.Payload, nil)
	responseStr := string(response)
	fmt.Println("[Server]:", responseStr)

	var offset int64 = 0
	fmt.Sscanf(responseStr, "Ready to receive file at offset %d", &offset)

	// Step 3: Open file
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[Client] Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	if offset > 0 {
		file.Seek(offset, io.SeekStart)
	}

	// Step 4: Optional compression
	var reader io.Reader = file
	if useGzip {
		pr, pw := io.Pipe()
		go func() {
			gw := gzip.NewWriter(pw)
			_, err := io.Copy(gw, file)
			gw.Close()
			pw.Close()
			if err != nil {
				log.Printf("[Client] GZIP compression error: %v", err)
			}
		}()
		reader = pr
	}

	// Step 5: Stream data
	buffer := make([]byte, 1024)
	for {
		n, err := reader.Read(buffer)
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

	// Step 6: EOF signal
	nonce, _ = crypto.GenerateNonce()
	ciphertext, _ = crypto.Encrypt(sessionKey, nonce, []byte(protocol.UploadEndMarker), nil)
	frame, _ = protocol.NewFrameWithStream(2, protocol.TypeData, nonce, ciphertext)
	frameBytes, _ = frame.Encode()
	w.Write(frameBytes)
	w.Flush()

	fmt.Println("[Client] Upload complete!")
}

func handleDownload(r *bufio.Reader, w *bufio.Writer, sessionKey [32]byte, command string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		fmt.Println("[Client] Usage: download <filename>")
		return
	}
	filename := parts[1]

	// Step 1: Send "download <filename>" request
	nonce, _ := crypto.GenerateNonce()
	ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(command), nil)
	frame, _ := protocol.NewFrameWithStream(2, protocol.TypeData, nonce, ciphertext)
	frameBytes, _ := frame.Encode()
	w.Write(frameBytes)
	w.Flush()

	// Step 2: Determine output file name
	outputName := filename + ".downloaded"
	if strings.HasSuffix(filename, ".gz") {
		outputName = filename // .gz dosyası olduğu gibi indirilsin
	}

	// Step 3: Prepare to receive and write chunks
	outFile, err := os.Create(outputName)
	if err != nil {
		fmt.Printf("[Client] Failed to create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	for {
		frame, err := protocol.Decode(r)
		if err != nil {
			fmt.Printf("[Client] Failed to read download chunk: %v\n", err)
			return
		}
		plain, err := crypto.Decrypt(sessionKey, frame.Nonce, frame.Payload, nil)
		if err != nil {
			fmt.Printf("[Client] Failed to decrypt chunk: %v\n", err)
			return
		}
		if string(plain) == protocol.UploadEndMarker {
			break
		}
		_, err = outFile.Write(plain)
		if err != nil {
			fmt.Printf("[Client] Failed to write to file: %v\n", err)
			return
		}
	}

	fmt.Printf("[Client] Download complete: %s\n", outputName)
	if strings.HasSuffix(outputName, ".gz") {
		fmt.Println("[Client] GZIP file detected. You can extract it manually with 'gunzip', 'gzip -d', or a file archiver.")
	}
}
