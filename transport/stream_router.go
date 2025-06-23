package transport

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"ztp/crypto"
	"ztp/protocol"
)

const (
	PriorityControl = 1
	PriorityChat    = 5
)

type RateLimiter struct {
	rate       int
	burst      int
	tokens     int
	lastRefill time.Time
	lock       sync.Mutex
}

type StreamMetrics struct {
	Messages     int
	BytesIn      int
	BytesOut     int
	DecryptFails int
}

func NewRateLimiter(rate int, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastRefill: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	newTokens := int(elapsed * float64(rl.rate))

	if newTokens > 0 {
		rl.tokens = min(rl.tokens+newTokens, rl.burst)
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type StreamRouter struct {
	timers        map[uint32]*time.Timer
	priorities    map[uint32]int
	rateLimits    map[uint32]*RateLimiter
	sessionKey    [32]byte
	writer        *bufio.Writer
	uploadManager *UploadManager
	usedNonces    map[string]struct{}
	metrics       map[uint32]*StreamMetrics
	lock          sync.RWMutex
	roles         map[uint32]string
	replayBuffer  *ReplayBuffer
	streamChans   map[uint32]chan *protocol.Frame
	names         map[uint32]string
}

func NewStreamRouter(sessionKey [32]byte, writer *bufio.Writer) *StreamRouter {
	return &StreamRouter{
		timers:        make(map[uint32]*time.Timer),
		priorities:    make(map[uint32]int),
		rateLimits:    make(map[uint32]*RateLimiter),
		sessionKey:    sessionKey,
		writer:        writer,
		uploadManager: NewUploadManager(),
		usedNonces:    make(map[string]struct{}),
		metrics:       make(map[uint32]*StreamMetrics),
		roles:         make(map[uint32]string), // tracks roles for each stream
		replayBuffer:  NewReplayBuffer(1000),   // tracks last 1000 nonces
		streamChans:   make(map[uint32]chan *protocol.Frame),
		names:         make(map[uint32]string), // tracks stream names
	}
}

func (sr *StreamRouter) handleFrameDispatch(streamID uint32, frame *protocol.Frame) {
	sr.lock.RLock()
	priority, hasPriority := sr.priorities[streamID]
	sr.lock.RUnlock()

	if !hasPriority {
		log.Printf("[Router] Unknown stream %d: priority not set", streamID)
		return
	}

	plaintext, err := crypto.Decrypt(sr.sessionKey, frame.Nonce, frame.Payload, nil)
	if err != nil {
		log.Printf("[Router] Stream %d decryption failed: %v", streamID, err)
		if m, ok := sr.metrics[streamID]; ok {
			m.DecryptFails++
		}
		return
	}
	message := string(plaintext)

	if sr.uploadManager.IsUploading(streamID) {
		if sr.uploadManager.HandleChunk(streamID, plaintext) {
			sr.sendResponse(streamID, "Upload complete")
			sr.CloseStream(streamID) //  graceful close
		}
		return
	}

	switch priority {
	case PriorityControl:
		if strings.HasPrefix(message, "upload ") || strings.HasPrefix(message, "upload-gzip ") {
			sr.startUpload(streamID, message)
		} else if strings.HasPrefix(message, "download ") {
			sr.startDownload(streamID, message)
		} else {
			sr.handleControlCommand(streamID, message)
		}
	default:
		sr.handleChatMessage(streamID, message)
	}
}

func (sr *StreamRouter) Dispatch(frame *protocol.Frame) {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	nonceKey := string(frame.Nonce[:])
	if sr.replayBuffer.Seen(nonceKey) {
		log.Printf("[Router] Replay detected for nonce %x, stream %d", frame.Nonce, frame.StreamID)
		sr.resetTimer(frame.StreamID)
		return
	}
	sr.usedNonces[nonceKey] = struct{}{}

	if !sr.allowFrame(frame.StreamID) {
		log.Printf("[RateLimit] Stream %d exceeded rate limit, dropping frame", frame.StreamID)
		return
	}

	if _, ok := sr.metrics[frame.StreamID]; !ok {
		sr.metrics[frame.StreamID] = &StreamMetrics{}
	}
	sr.metrics[frame.StreamID].Messages++
	sr.metrics[frame.StreamID].BytesIn += len(frame.Payload)

	if _, ok := sr.priorities[frame.StreamID]; !ok {
		// Guess priority by command type (peek into payload)
		plain, err := crypto.Decrypt(sr.sessionKey, frame.Nonce, frame.Payload, nil)
		if err != nil {
			sr.priorities[frame.StreamID] = PriorityChat
		} else {
			cmd := strings.ToLower(string(plain))
			if strings.HasPrefix(cmd, "ping") ||
				strings.HasPrefix(cmd, "upload") ||
				strings.HasPrefix(cmd, "download") ||
				strings.HasPrefix(cmd, "status") ||
				strings.HasPrefix(cmd, "resume") ||
				strings.HasPrefix(cmd, "info") ||
				strings.HasPrefix(cmd, "time") ||
				strings.HasPrefix(cmd, "list") ||
				strings.HasPrefix(cmd, "chatlist") {
				sr.priorities[frame.StreamID] = PriorityControl
			} else {
				sr.priorities[frame.StreamID] = PriorityChat
			}
		}
		sr.timers[frame.StreamID] = sr.startTimer(frame.StreamID)
		sr.rateLimits[frame.StreamID] = NewRateLimiter(10, 20)
	}

	if _, exists := sr.names[frame.StreamID]; !exists {
		sr.names[frame.StreamID] = sr.names[1]
	}

	ch, exists := sr.streamChans[frame.StreamID]
	if !exists {
		ch = make(chan *protocol.Frame, 10)
		sr.streamChans[frame.StreamID] = ch
		go sr.handleStream(frame.StreamID, ch)
	}
	ch <- frame
}

func (sr *StreamRouter) startUpload(streamID uint32, command string) {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		sr.sendResponse(streamID, "Usage: upload <filename> or upload --gzip <filename>")
		return
	}

	isGzipped := false
	filename := ""

	// Desteklenen formatlar:
	// 1. upload file.txt
	// 2. upload --gzip file.txt
	// 3. upload-gzip file.txt
	if parts[0] == "upload-gzip" && len(parts) == 2 {
		isGzipped = true
		filename = parts[1]
	} else if parts[0] == "upload" && len(parts) == 3 && parts[1] == "--gzip" {
		isGzipped = true
		filename = parts[2]
	} else if parts[0] == "upload" && len(parts) == 2 {
		isGzipped = false
		filename = parts[1]
	} else {
		sr.sendResponse(streamID, "Invalid upload command format")
		return
	}

	offset, err := sr.uploadManager.StartUpload(streamID, filename)
	if err != nil {
		sr.sendResponse(streamID, fmt.Sprintf("Failed to start upload: %v", err))
		return
	}

	// Mark stream as gzipped if needed
	sr.uploadManager.lock.Lock()
	if state, ok := sr.uploadManager.activeUploads[streamID]; ok {
		state.IsGzipped = isGzipped
	}
	sr.uploadManager.lock.Unlock()

	log.Printf("[Router] Stream %d ready to receive file: %s at offset %d (gzip: %v)", streamID, filename, offset, isGzipped)
	sr.sendResponse(streamID, fmt.Sprintf("Ready to receive file at offset %d", offset))
}

func (sr *StreamRouter) startDownload(streamID uint32, command string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		sr.sendResponse(streamID, "Invalid download command")
		return
	}
	filename := parts[1]
	file, err := os.Open("server_files/" + filename)
	if err != nil {
		sr.sendResponse(streamID, fmt.Sprintf("Failed to open file: %v", err))
		return
	}
	defer file.Close()

	buffer := make([]byte, 1024)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			sr.sendResponse(streamID, "Error reading file")
			return
		}
		if n == 0 {
			break
		}
		sr.sendResponse(streamID, string(buffer[:n]))
	}

	sr.sendResponse(streamID, protocol.UploadEndMarker)
	log.Printf("[Router] Finished sending file %s to Stream %d", filename, streamID)
	sr.CloseStream(streamID) // ✅ graceful close after sending EOF
}

func (sr *StreamRouter) handleControlCommand(streamID uint32, command string) {
	command = strings.TrimSpace(command)
	cmdParts := strings.Fields(command)
	if len(cmdParts) == 0 {
		sr.sendResponse(streamID, "Empty control command")
		return
	}

	cmd := strings.ToLower(cmdParts[0])
	var response string

	switch cmd {
	case "ping":
		response = "pong"
	case "status":
		response = "server OK"
	case "time":
		response = time.Now().UTC().Format(time.RFC3339)
	case "list":
		files, err := os.ReadDir("server_files")
		if err != nil {
			response = "Failed to list files"
		} else {
			names := make([]string, 0)
			for _, f := range files {
				if !f.IsDir() {
					names = append(names, f.Name())
				}
			}
			if len(names) == 0 {
				response = "No files available"
			} else {
				response = "Files: " + strings.Join(names, ", ")
			}
		}
	case "info":
		response = "ZTP Server v1.0 - Secure Transport Protocol"
	case "echo":
		if len(cmdParts) > 1 {
			response = strings.Join(cmdParts[1:], " ")
		} else {
			response = "No message to echo"
		}
	case "resume":
		if len(cmdParts) != 2 {
			response = "Usage: resume <client_id>"
			break
		}
		clientID := cmdParts[1]
		sess, ok := sessions.Load(clientID)
		if !ok {
			response = "No valid session found for " + clientID
			break
		}
		sr.sessionKey = sess.Key
		sr.names[streamID] = clientID
		response = "Session resumed for " + clientID
	case "chatlist":
		sessions.lock.RLock()
		ids := make([]string, 0)
		for id := range sessions.store {
			ids = append(ids, id)
		}
		sessions.lock.RUnlock()
		if len(ids) == 0 {
			response = "No active clients"
		} else {
			response = "Active clients: " + strings.Join(ids, ", ")
		}
	case "chat":
		// "chat" komutu sonrası mesaj var mı kontrol et
		msg := strings.TrimSpace(strings.TrimPrefix(command, "chat"))
		if msg == "" {
			sr.sendResponse(streamID, "⚠️ Empty chat message.")
			return
		}

		sr.handleChatMessage(streamID, msg)
		return
	default:
		response = "Unknown command"
	}

	log.Printf("[Router] Stream %d: Control -> %s", streamID, command)
	sr.sendResponse(streamID, response)
}

// Eğer mesaj "@clientID mesaj" şeklindeyse → Private Message
// Eğer mesaj "chat mesaj" şeklindeyse → Broadcast Chat
func (sr *StreamRouter) handleChatMessage(streamID uint32, message string) {
	sender := sr.names[streamID]
	if sender == "" {
		sender = "unknown"
	}

	// Eğer mesaj "@clientID mesaj" şeklindeyse → Private Message
	if strings.HasPrefix(message, "@") {
		parts := strings.SplitN(message, " ", 2)
		if len(parts) != 2 {
			sr.sendResponse(streamID, "⚠️ Usage: @clientID your message")
			return
		}

		targetID := strings.TrimPrefix(parts[0], "@")
		content := parts[1]

		targetSess, ok := sessions.Load(targetID) // 🔁 Doğru yöntem
		if !ok || targetSess.Writer == nil {
			sr.sendResponse(streamID, fmt.Sprintf("⚠️ Client @%s not found or offline", targetID))
			return
		}

		msg := fmt.Sprintf("[PM from %s]: %s", sender, content)
		nonce, _ := crypto.GenerateNonce()
		encrypted, _ := crypto.Encrypt(targetSess.Key, nonce, []byte(msg), nil)
		frame, _ := protocol.NewFrameWithStream(3, protocol.TypeData, nonce, encrypted)
		data, _ := frame.Encode()

		targetSess.Writer.Write(data)
		targetSess.Writer.Flush()

		sr.sendResponse(streamID, fmt.Sprintf("✅ Sent private message to @%s", targetID))
		log.Printf("[PM] %s -> %s: %s", sender, targetID, content)
		return
	}

	// Broadcast Chat
	broadcastMsg := fmt.Sprintf("[Chat] %s: %s", sender, message)

	sessions.lock.RLock()
	defer sessions.lock.RUnlock()

	for id, sess := range sessions.store {
		if id == sender || sess.Writer == nil {
			continue
		}

		nonce, err := crypto.GenerateNonce()
		if err != nil {
			continue
		}
		encrypted, err := crypto.Encrypt(sess.Key, nonce, []byte(broadcastMsg), nil)
		if err != nil {
			continue
		}
		frame, err := protocol.NewFrameWithStream(3, protocol.TypeData, nonce, encrypted)
		if err != nil {
			continue
		}
		data, err := frame.Encode()
		if err != nil {
			continue
		}

		sess.Writer.Write(data)
		sess.Writer.Flush()
	}

	sr.sendResponse(streamID, "✅ Broadcast sent to all connected clients")
	log.Printf("[Broadcast] %s: %s", sender, message)
}

func (sr *StreamRouter) allowFrame(streamID uint32) bool {
	rl, ok := sr.rateLimits[streamID]
	if !ok {
		return true
	}
	return rl.Allow()
}

func (sr *StreamRouter) startTimer(streamID uint32) *time.Timer {
	return time.AfterFunc(30*time.Second, func() {

		log.Printf("[Router] Stream %d timed out", streamID)
		sr.CloseStream(streamID)
	})

}

func (sr *StreamRouter) resetTimer(streamID uint32) {
	if timer, ok := sr.timers[streamID]; ok {
		timer.Reset(30 * time.Second)
	}
}

func (sr *StreamRouter) handleStream(streamID uint32, ch chan *protocol.Frame) {
	log.Printf("[Router] New handler for Stream %d", streamID)
	defer log.Printf("[Router] Handler closed for Stream %d", streamID)

	for frame := range ch {
		plaintext, err := crypto.Decrypt(sr.sessionKey, frame.Nonce, frame.Payload, nil)
		if err != nil {
			log.Printf("[Router] Stream %d decryption failed: %v", streamID, err)
			if m, ok := sr.metrics[streamID]; ok {
				m.DecryptFails++
			}
			continue
		}
		message := string(plaintext)

		// Priority guessing if not already set
		sr.lock.Lock()
		if _, ok := sr.priorities[streamID]; !ok {
			cmd := strings.ToLower(message)
			if strings.HasPrefix(cmd, "ping") ||
				strings.HasPrefix(cmd, "upload") ||
				strings.HasPrefix(cmd, "download") ||
				strings.HasPrefix(cmd, "status") ||
				strings.HasPrefix(cmd, "resume") ||
				strings.HasPrefix(cmd, "list") ||
				strings.HasPrefix(cmd, "info") ||
				strings.HasPrefix(cmd, "echo") {
				sr.priorities[streamID] = PriorityControl
			} else {
				sr.priorities[streamID] = PriorityChat
			}
		}
		sr.lock.Unlock()

		if sr.uploadManager.IsUploading(streamID) {
			if sr.uploadManager.HandleChunk(streamID, plaintext) {
				sr.sendResponse(streamID, "Upload complete")
				sr.CloseStream(streamID)
			}
			continue
		}

		if sr.priorities[streamID] == PriorityControl {
			if strings.HasPrefix(message, "upload ") || strings.HasPrefix(message, "upload-gzip ") {
				sr.startUpload(streamID, message)
			} else if strings.HasPrefix(message, "download ") {
				sr.startDownload(streamID, message)
			} else {
				sr.handleControlCommand(streamID, message)
			}
		} else {
			sr.handleChatMessage(streamID, message)
		}
	}
}

func (sr *StreamRouter) sendResponse(streamID uint32, message string) {
	nonce, err := crypto.GenerateNonce()
	if err != nil {
		log.Printf("[Router] Failed to generate nonce: %v", err)
		return
	}
	ciphertext, err := crypto.Encrypt(sr.sessionKey, nonce, []byte(message), nil)
	if err != nil {
		log.Printf("[Router] Failed to encrypt response: %v", err)
		return
	}
	frame, err := protocol.NewFrameWithStream(streamID, protocol.TypeData, nonce, ciphertext)
	if err != nil {
		log.Printf("[Router] Failed to create frame: %v", err)
		return
	}
	encoded, err := frame.Encode()
	if err != nil {
		log.Printf("[Router] Failed to encode frame: %v", err)
		return
	}
	if _, err := sr.writer.Write(encoded); err != nil {
		log.Printf("[Router] Failed to send frame: %v", err)
		return
	}
	sr.writer.Flush()

	if m, ok := sr.metrics[streamID]; ok {
		m.BytesOut += len(encoded)
	}

	log.Printf("[Router] Response sent to Stream %d", streamID)
}

func (sr *StreamRouter) CloseStream(streamID uint32) {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	if timer, ok := sr.timers[streamID]; ok {
		timer.Stop()
		delete(sr.timers, streamID)
	}
	delete(sr.priorities, streamID)
	sr.uploadManager.AbortUpload(streamID)

	if ch, ok := sr.streamChans[streamID]; ok {
		close(ch)
		delete(sr.streamChans, streamID)
	}

	if m, ok := sr.metrics[streamID]; ok {
		log.Printf("[Metrics] Stream %d: %d msgs | %dB in | %dB out | %d decrypt fails",
			streamID, m.Messages, m.BytesIn, m.BytesOut, m.DecryptFails)
		delete(sr.metrics, streamID)
	}
	log.Printf("[Router] Closing stream %d", streamID)
}

func (sr *StreamRouter) CloseAll() {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	for id, timer := range sr.timers {
		timer.Stop()
		delete(sr.timers, id)
	}
	sr.priorities = make(map[uint32]int)
	sr.uploadManager = NewUploadManager()
	sr.usedNonces = make(map[string]struct{})
	sr.metrics = make(map[uint32]*StreamMetrics)
}
