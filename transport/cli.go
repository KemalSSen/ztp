package transport

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"ztp/crypto"
	"ztp/identity"
	"ztp/protocol"
)

const UploadEndMarker = "[EOF]"

func SendSimpleCommand(addr string, streamID uint32, command string) error {
	conn, sessionKey, r, w, err := dialAndAuthenticate(addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := sendEncryptedFrame(w, sessionKey, streamID, command); err != nil {
		return err
	}

	frame, err := protocol.Decode(r)
	if err != nil {
		return err
	}
	reply, err := crypto.Decrypt(sessionKey, frame.Nonce, frame.Payload, nil)
	if err != nil {
		return err
	}
	fmt.Printf("[Server Reply]: %s\n", string(reply))
	return nil
}

func SendChatMessage(addr string, streamID uint32, message string) {
	conn, sessionKey, r, w, err := dialAndAuthenticate(addr)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	defer conn.Close()

	if err := sendEncryptedFrame(w, sessionKey, streamID, message); err != nil {
		log.Fatalf("Failed to send: %v", err)
	}

	frame, err := protocol.Decode(r)
	if err != nil {
		log.Fatalf("Failed to read reply: %v", err)
	}
	reply, _ := crypto.Decrypt(sessionKey, frame.Nonce, frame.Payload, nil)
	fmt.Printf("[Chat Reply]: %s\n", string(reply))
}

func RunUploadClient(addr string, streamID uint32, filename string) {
	conn, sessionKey, _, w, err := dialAndAuthenticate(addr)
	if err != nil {
		log.Fatalf("Upload failed: %v", err)
	}
	defer conn.Close()

	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	sendEncryptedFrame(w, sessionKey, streamID, "upload "+filename)
	time.Sleep(300 * time.Millisecond)

	buf := make([]byte, 1024)
	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatalf("Failed reading file: %v", err)
		}
		if n == 0 {
			break
		}
		sendEncryptedFrame(w, sessionKey, streamID, string(buf[:n]))
	}
	sendEncryptedFrame(w, sessionKey, streamID, UploadEndMarker)
	fmt.Println("[Client] Upload complete.")
	time.Sleep(500 * time.Millisecond)
}

func RunDownloadClient(addr string, streamID uint32, filename string) {
	conn, sessionKey, r, w, err := dialAndAuthenticate(addr)
	if err != nil {
		log.Fatalf("Download failed: %v", err)
	}
	defer conn.Close()

	sendEncryptedFrame(w, sessionKey, streamID, "download "+filename)

	output, _ := os.Create("downloaded_" + filename)
	defer output.Close()

	for {
		frame, err := protocol.Decode(r)
		if err != nil {
			log.Fatalf("Download error: %v", err)
		}
		chunk, _ := crypto.Decrypt(sessionKey, frame.Nonce, frame.Payload, nil)
		if string(chunk) == UploadEndMarker {
			break
		}
		output.Write(chunk)
	}
	fmt.Printf("[Client] Downloaded and saved as downloaded_%s\n", filename)
}

func dialAndAuthenticate(addr string) (net.Conn, [32]byte, *bufio.Reader, *bufio.Writer, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, [32]byte{}, nil, nil, err
	}
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	keys, _ := crypto.GenerateKeyPair()
	w.Write(keys.Public[:])
	w.Flush()

	serverPub := make([]byte, 32)
	r.Read(serverPub)
	peer, _ := crypto.DecodePublicKey(serverPub)
	shared, _ := crypto.ComputeSharedKey(keys.Private, peer)
	sessionKey := crypto.DeriveSessionKey(shared, []byte("ztp-handshake"))

	token, _ := identity.CreateToken("cli", "admin", 2*time.Minute)
	nonce, _ := crypto.GenerateNonce()
	encrypted, _ := crypto.Encrypt(sessionKey, nonce, []byte(token), nil)
	frame, _ := protocol.NewFrameWithStream(1, protocol.TypeHandshakeInit, nonce, encrypted)
	data, _ := frame.Encode()
	w.Write(data)
	w.Flush()

	return conn, sessionKey, r, w, nil
}

func sendEncryptedFrame(w *bufio.Writer, sessionKey [32]byte, streamID uint32, message string) error {
	nonce, _ := crypto.GenerateNonce()
	ciphertext, _ := crypto.Encrypt(sessionKey, nonce, []byte(message), nil)
	frame, _ := protocol.NewFrameWithStream(streamID, protocol.TypeData, nonce, ciphertext)
	data, _ := frame.Encode()
	_, err := w.Write(data)
	w.Flush()
	return err
}
