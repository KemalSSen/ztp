package transport

import (
	"fmt"
	"os"
	"sync"
	"ztp/protocol"
)

// UploadManager handles multiple concurrent uploads safely
type UploadManager struct {
	activeUploads map[uint32]*os.File
	lock          sync.RWMutex
}

func NewUploadManager() *UploadManager {
	return &UploadManager{
		activeUploads: make(map[uint32]*os.File),
	}
}

// StartUpload initializes a new file upload
func (um *UploadManager) StartUpload(streamID uint32, filename string) error {
	um.lock.Lock()
	defer um.lock.Unlock()

	if _, exists := um.activeUploads[streamID]; exists {
		return fmt.Errorf("upload already active on stream %d", streamID)
	}

	// Ensure server_files/ directory exists
	if _, err := os.Stat("server_files"); os.IsNotExist(err) {
		if err := os.MkdirAll("server_files", 0755); err != nil {
			return fmt.Errorf("failed to create server_files directory: %v", err)
		}
	}

	file, err := os.Create("server_files/" + filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}

	um.activeUploads[streamID] = file
	return nil
}

// HandleChunk processes incoming chunks.
// Returns true if upload is completed (EOF received).
func (um *UploadManager) HandleChunk(streamID uint32, chunk []byte) bool {
	um.lock.RLock()
	file, exists := um.activeUploads[streamID]
	um.lock.RUnlock()

	if !exists {
		return false
	}

	// Check for EOF marker
	if string(chunk) == protocol.UploadEndMarker {
		um.lock.Lock()
		defer um.lock.Unlock()

		file.Close()
		delete(um.activeUploads, streamID)
		return true
	}

	// Otherwise, write chunk normally
	if _, err := file.Write(chunk); err != nil {
		fmt.Printf("[UploadManager] Failed to write chunk for Stream %d: %v\n", streamID, err)
	}

	return false
}

// IsUploading checks if a stream is currently uploading
func (um *UploadManager) IsUploading(streamID uint32) bool {
	um.lock.RLock()
	defer um.lock.RUnlock()

	_, exists := um.activeUploads[streamID]
	return exists
}

// AbortUpload forcibly closes and cancels a file upload
func (um *UploadManager) AbortUpload(streamID uint32) {
	um.lock.Lock()
	defer um.lock.Unlock()

	if file, exists := um.activeUploads[streamID]; exists {
		file.Close()
		delete(um.activeUploads, streamID)
	}
}
