// testclient runs a test client for use in the unit test. We run this in a
// separate process in order to test unclean disconnects.
package main

import (
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	data = []byte("Hello there strange and wonderful benchmarking world!")
)

func main() {
	log.Printf("Running test client: %v\n", os.Args)
	addr := os.Args[1]
	iters, _ := strconv.Atoi(os.Args[2])

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Unable to dial client proxy: %v", err)
	}

	// Write
	go func() {
		for j := 0; j < iters; j++ {
			_, err := conn.Write(data)
			if err != nil {
				log.Fatalf("%d Unable to write: %v", j, err)
			}
		}
	}()

	// Read (should stop automatically due to TCP keepalive)
	buf := make([]byte, len(data))
	for i := 0; i < iters; i++ {
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Don't terminate ourselves, let test kill us
	time.Sleep(5 * time.Hour)
}
