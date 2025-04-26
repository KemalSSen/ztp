package main

import (
	"log"
	"ztp/transport"
)

func main() {
	if err := transport.StartServer(":9999"); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
