package main

import (
	"log"
	"ztp/transport"
)

func main() {
	err := transport.StartClient("localhost:9999")
	if err != nil {
		log.Fatalf("Client error: %v", err)
	}
}
