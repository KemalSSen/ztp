package transport_test

import (
	"os"
	"path/filepath"
	"testing"

	"ztp/transport"
)

func TestStartUpload_NewFile(t *testing.T) {
	cleanupDir(t)
	um := transport.NewUploadManager()
	offset, err := um.StartUpload(1001, "testfile.txt")
	if err != nil {
		t.Fatalf("StartUpload failed: %v", err)
	}
	if offset != 0 {
		t.Errorf("Expected offset 0 for new file, got %d", offset)
	}
	um.AbortUpload(1001)
}

func TestStartUpload_Resume(t *testing.T) {
	cleanupDir(t)
	filePath := filepath.Join("server_files", "resumable.txt")
	dummyData := []byte("hello")
	if err := os.WriteFile(filePath, dummyData, 0644); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	um := transport.NewUploadManager()
	offset, err := um.StartUpload(1002, "resumable.txt")
	if err != nil {
		t.Fatalf("Resume upload failed: %v", err)
	}
	if offset != int64(len(dummyData)) {
		t.Errorf("Expected offset %d, got %d", len(dummyData), offset)
	}
	um.AbortUpload(1002)
}

func TestHandleChunk_WriteAndEOF(t *testing.T) {
	cleanupDir(t)
	um := transport.NewUploadManager()
	_, err := um.StartUpload(1003, "write.txt")
	if err != nil {
		t.Fatalf("StartUpload failed: %v", err)
	}

	completed := um.HandleChunk(1003, []byte("data"))
	if completed {
		t.Errorf("Unexpected completion on data chunk")
	}
	completed = um.HandleChunk(1003, []byte("[EOF]"))
	if !completed {
		t.Errorf("Expected completion on EOF")
	}
}

func TestAbortUpload(t *testing.T) {
	cleanupDir(t)
	um := transport.NewUploadManager()
	_, err := um.StartUpload(1004, "abort.txt")
	if err != nil {
		t.Fatalf("StartUpload failed: %v", err)
	}
	um.AbortUpload(1004)
	if um.IsUploading(1004) {
		t.Errorf("Expected stream 1004 to be aborted")
	}
}

func cleanupDir(t *testing.T) {
	t.Helper()
	_ = os.MkdirAll("server_files", 0755)
	dir, _ := os.ReadDir("server_files")
	for _, f := range dir {
		_ = os.Remove(filepath.Join("server_files", f.Name()))
	}
}
