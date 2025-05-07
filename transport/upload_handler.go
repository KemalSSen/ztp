package transport

import (
	"fmt"
	"os"
	"sync"
	"ztp/protocol"
)

// UploadState tracks partial upload information
type UploadState struct {
	File   *os.File
	Offset int64
}

// UploadManager handles resumable uploads by stream
type UploadManager struct {
	activeUploads map[uint32]*UploadState
	lock          sync.RWMutex
}

func NewUploadManager() *UploadManager {
	return &UploadManager{
		activeUploads: make(map[uint32]*UploadState),
	}
}

// StartUpload prepares to write to a file (appends if exists)
func (um *UploadManager) StartUpload(streamID uint32, filename string) (int64, error) {
	um.lock.Lock()
	defer um.lock.Unlock()

	if _, exists := um.activeUploads[streamID]; exists {
		return 0, fmt.Errorf("upload already active on stream %d", streamID)
	}

	// Ensure server_files directory exists
	if _, err := os.Stat("server_files"); os.IsNotExist(err) {
		if err := os.MkdirAll("server_files", 0755); err != nil {
			return 0, fmt.Errorf("failed to create server_files directory: %v", err)
		}
	}

	fullPath := "server_files/" + filename
	var file *os.File
	var offset int64 = 0

	if stat, err := os.Stat(fullPath); err == nil {
		file, err = os.OpenFile(fullPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return 0, fmt.Errorf("failed to open file for append: %v", err)
		}
		offset = stat.Size()
	} else {
		file, err = os.Create(fullPath)
		if err != nil {
			return 0, fmt.Errorf("failed to create file: %v", err)
		}
	}

	um.activeUploads[streamID] = &UploadState{
		File:   file,
		Offset: offset,
	}
	return offset, nil
}

func (um *UploadManager) HandleChunk(streamID uint32, chunk []byte) bool {
	um.lock.RLock()
	state, exists := um.activeUploads[streamID]
	um.lock.RUnlock()

	if !exists {
		return false
	}

	if string(chunk) == protocol.UploadEndMarker {
		um.lock.Lock()
		defer um.lock.Unlock()
		state.File.Close()
		delete(um.activeUploads, streamID)
		return true
	}

	n, err := state.File.Write(chunk)
	if err != nil {
		fmt.Printf("[UploadManager] Failed to write chunk: %v\n", err)
		return false
	}
	state.Offset += int64(n)
	return false
}

func (um *UploadManager) IsUploading(streamID uint32) bool {
	um.lock.RLock()
	defer um.lock.RUnlock()
	_, exists := um.activeUploads[streamID]
	return exists
}

func (um *UploadManager) AbortUpload(streamID uint32) {
	um.lock.Lock()
	defer um.lock.Unlock()

	if state, ok := um.activeUploads[streamID]; ok {
		state.File.Close()
		delete(um.activeUploads, streamID)
	}
}
