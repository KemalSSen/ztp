package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"ztp/transport"
)

func main() {
	addr := flag.String("addr", "localhost:9999", "Address of the ZTP server")
	id := flag.String("id", "default-client", "Client identity")

	flag.Parse()

	if flag.NArg() < 1 {
		if err := transport.StartClient(*addr, *id); err != nil {
			log.Fatalf("[ztp-client] Error: %v", err)
		}

		fmt.Println("Usage:")
		fmt.Println("  ztp-client --addr <host:port> <command> [args...]")
		fmt.Println("Examples:")
		fmt.Println("  ztp-client --addr localhost:9999 ping")
		fmt.Println("  ztp-client --addr localhost:9999 upload file.txt")
		fmt.Println("  ztp-client --addr localhost:9999 download file.txt")
		fmt.Println("  ztp-client --addr localhost:9999 chat \"hello there!\"")
		os.Exit(1)
	}

	command := flag.Arg(0)
	args := flag.Args()[1:]
	streamID := generateStreamID()

	switch command {
	case "ping", "status", "time", "info", "list":
		runSimple(*addr, streamID, command)
	case "echo":
		if len(args) == 0 {
			log.Fatal("Usage: echo <message>")
		}
		runSimple(*addr, streamID, "echo "+strings.Join(args, " "))
	case "upload":
		if len(args) != 1 {
			log.Fatal("Usage: upload <filename>")
		}
		transport.RunUploadClient(*addr, streamID, args[0])
	case "download":
		if len(args) != 1 {
			log.Fatal("Usage: download <filename>")
		}
		transport.RunDownloadClient(*addr, streamID, args[0])
	case "chat":
		if len(args) == 0 {
			log.Fatal("Usage: chat <message>")
		}
		transport.SendChatMessage(*addr, streamID, strings.Join(args, " "))
	default:
		log.Fatalf("Unknown command: %s", command)
	}
}

func runSimple(addr string, streamID uint32, cmd string) {
	if err := transport.SendSimpleCommand(addr, streamID, cmd); err != nil {
		log.Fatalf("[ztp-client] Error: %v", err)
	}
}

func generateStreamID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(100 + time.Now().UnixNano()%10000) // fallback
	}
	id := binary.BigEndian.Uint32(b[:])
	if id <= 2 {
		id += 3
	}
	return id % math.MaxUint32
}
