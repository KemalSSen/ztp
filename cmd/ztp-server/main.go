package main

import (
	"flag"
	"log"

	"ztp/transport"
)

func main() {
	addr := flag.String("addr", ":9999", "Address to listen on")
	flag.Parse()

	log.Printf("[ztp-server] Starting server on %s...", *addr)
	if err := transport.StartServer(*addr); err != nil {
		log.Fatalf("[ztp-server] Server error: %v", err)
	}
}
