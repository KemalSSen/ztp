package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	CurrentVersion = 1

	TypeHandshakeInit uint16 = 0x01
	TypeHandshakeAck  uint16 = 0x02
	TypeData          uint16 = 0x03
	TypeClose         uint16 = 0x04

	// New Frame Types for File Transfers
	TypeUploadInit    uint16 = 0x10
	TypeUploadChunk   uint16 = 0x11
	TypeUploadDone    uint16 = 0x12
	TypeDownloadInit  uint16 = 0x13
	TypeDownloadChunk uint16 = 0x14
	TypeDownloadDone  uint16 = 0x15

	NonceSize      = 12
	HeaderSize     = 28
	MaxPayloadSize = 65535
)

// Frame represents a structured protocol message
type Frame struct {
	Version  uint16
	Type     uint16
	StreamID uint32
	Nonce    [12]byte
	Length   uint32
	Reserved uint32
	Payload  []byte
}

func NewFrame(msgType uint16, nonce [12]byte, payload []byte) (*Frame, error) {
	return NewFrameWithStream(1, msgType, nonce, payload) // default StreamID = 1
}

func NewFrameWithStream(streamID uint32, msgType uint16, nonce [12]byte, payload []byte) (*Frame, error) {
	if len(payload) > MaxPayloadSize {
		return nil, errors.New("payload too large")
	}
	return &Frame{
		Version:  CurrentVersion,
		Type:     msgType,
		StreamID: streamID,
		Nonce:    nonce,
		Length:   uint32(len(payload)),
		Reserved: 0,
		Payload:  payload,
	}, nil
}

// Encode serializes the frame into bytes
func (f *Frame) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, f.Version)
	binary.Write(buf, binary.BigEndian, f.Type)
	binary.Write(buf, binary.BigEndian, f.StreamID)
	_, err := buf.Write(f.Nonce[:])
	if err != nil {
		return nil, err
	}
	binary.Write(buf, binary.BigEndian, f.Length)
	binary.Write(buf, binary.BigEndian, f.Reserved)
	buf.Write(f.Payload)
	return buf.Bytes(), nil
}

// Decode reads a frame from a stream
func Decode(r io.Reader) (*Frame, error) {
	head := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	buf := bytes.NewReader(head)

	f := &Frame{}
	binary.Read(buf, binary.BigEndian, &f.Version)
	binary.Read(buf, binary.BigEndian, &f.Type)
	binary.Read(buf, binary.BigEndian, &f.StreamID)
	if _, err := buf.Read(f.Nonce[:]); err != nil {
		return nil, err
	}
	binary.Read(buf, binary.BigEndian, &f.Length)
	binary.Read(buf, binary.BigEndian, &f.Reserved)

	if f.Length > MaxPayloadSize {
		return nil, errors.New("frame payload too large")
	}

	f.Payload = make([]byte, f.Length)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return nil, err
	}

	return f, nil
}
