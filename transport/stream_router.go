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

type StreamRouter struct {
	streams    map[uint32]chan *protocol.Frame
	timers     map[uint32]*time.Timer
	priorities map[uint32]int

	lock          sync.RWMutex
	sessionKey    [32]byte
	writer        *bufio.Writer
	uploadManager *UploadManager
}

func NewStreamRouter(sessionKey [32]byte, writer *bufio.Writer) *StreamRouter {
	return &StreamRouter{
		streams:       make(map[uint32]chan *protocol.Frame),
		timers:        make(map[uint32]*time.Timer),
		priorities:    make(map[uint32]int),
		sessionKey:    sessionKey,
		writer:        writer,
		uploadManager: NewUploadManager(),
	}
}

func (sr *StreamRouter) Dispatch(frame *protocol.Frame) {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	ch, exists := sr.streams[frame.StreamID]
	if !exists {
		ch = make(chan *protocol.Frame, 10)
		sr.streams[frame.StreamID] = ch
		sr.timers[frame.StreamID] = sr.startTimer(frame.StreamID)
		if frame.StreamID == 2 {
			sr.priorities[frame.StreamID] = PriorityControl
		} else {
			sr.priorities[frame.StreamID] = PriorityChat
		}
		go sr.handleStream(frame.StreamID, ch)
	}
	ch <- frame
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
			continue
		}
		message := string(plaintext)

		if sr.uploadManager.IsUploading(streamID) {
			if sr.uploadManager.HandleChunk(streamID, plaintext) {
				sr.sendResponse(streamID, "Upload complete")
			}
			continue
		}

		if sr.priorities[streamID] == PriorityControl {
			if strings.HasPrefix(message, "upload ") {
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

func (sr *StreamRouter) startUpload(streamID uint32, command string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		sr.sendResponse(streamID, "Invalid upload command")
		return
	}
	filename := parts[1]
	err := sr.uploadManager.StartUpload(streamID, filename)
	if err != nil {
		sr.sendResponse(streamID, fmt.Sprintf("Failed to start upload: %v", err))
		return
	}
	log.Printf("[Router] Stream %d ready to receive file: %s", streamID, filename)
	sr.sendResponse(streamID, "Ready to receive file")
}

func (sr *StreamRouter) startDownload(streamID uint32, command string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		sr.sendResponse(streamID, "Invalid download command")
		return
	}
	filename := parts[1]

	f, err := os.Open("server_files/" + filename)
	if err != nil {
		sr.sendResponse(streamID, fmt.Sprintf("Failed to open file: %v", err))
		return
	}
	defer f.Close()

	buffer := make([]byte, 1024)
	for {
		n, err := f.Read(buffer)
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
}

func (sr *StreamRouter) handleControlCommand(streamID uint32, command string) {
	cmdParts := strings.Fields(strings.ToLower(command))
	if len(cmdParts) == 0 {
		sr.sendResponse(streamID, "Empty control command")
		return
	}

	var response string
	switch cmdParts[0] {
	case "ping":
		response = "pong"
	case "status":
		response = "server OK"
	case "time":
		response = time.Now().UTC().Format(time.RFC3339)
	case "list":
		response = "Available: file1.txt, file2.txt, config.yaml"
	case "info":
		response = "ZTP Server v1.0 - Secure Transport Protocol"
	case "echo":
		if len(cmdParts) > 1 {
			response = strings.Join(cmdParts[1:], " ")
		} else {
			response = "No message to echo"
		}
	default:
		response = "Unknown command"
	}

	log.Printf("[Router] Stream %d: Control -> %s", streamID, command)
	sr.sendResponse(streamID, response)
}

func (sr *StreamRouter) handleChatMessage(streamID uint32, message string) {
	log.Printf("[Router] Stream %d: Chat -> %s", streamID, message)
	sr.sendResponse(streamID, message)
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
	log.Printf("[Router] Response sent to Stream %d", streamID)
}

func (sr *StreamRouter) CloseStream(streamID uint32) {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	if ch, ok := sr.streams[streamID]; ok {
		close(ch)
		delete(sr.streams, streamID)
	}
	if timer, ok := sr.timers[streamID]; ok {
		timer.Stop()
		delete(sr.timers, streamID)
	}
	delete(sr.priorities, streamID)
	sr.uploadManager.AbortUpload(streamID)
}

func (sr *StreamRouter) CloseAll() {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	for id, ch := range sr.streams {
		close(ch)
		delete(sr.streams, id)
	}
	for id, timer := range sr.timers {
		timer.Stop()
		delete(sr.timers, id)
	}
	sr.priorities = make(map[uint32]int)
	sr.uploadManager = NewUploadManager()
}
