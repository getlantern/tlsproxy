package main

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/getlantern/keyman"
)

var (
	data = []byte("Hello there strange and wonderful benchmarking world!")
)

func BenchmarkNoIdle(b *testing.B) {
	doBenchmark(b, 0)
}

func BenchmarkIdle(b *testing.B) {
	doBenchmark(b, 2*time.Hour)
}

func doBenchmark(b *testing.B, idleTimeout time.Duration) {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := pk.TLSCertificateFor("lantern", "lantern", time.Now().Add(24*time.Hour), false, nil)
	if err != nil {
		b.Fatal(err)
	}
	keyPair, err := tls.X509KeyPair(cert.PEMEncoded(), pk.PEMEncoded())
	if err != nil {
		b.Fatal(err)
	}
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
	}
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, listenErr := l.Accept()
			if listenErr != nil {
				return
			}
			// echo
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	sl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatal(err)
	}
	defer sl.Close()

	cl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatal(err)
	}
	defer cl.Close()

	go runServer(sl, l.Addr().String(), idleTimeout, serverConfig)
	go runClient(cl, sl.Addr().String(), idleTimeout, clientConfig)

	clientAddr := cl.Addr().String()

	b.ResetTimer()

	buf := make([]byte, len(data))
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", clientAddr)
		if err != nil {
			b.Fatalf("Unable to dial client proxy: %v", err)
		}
		for j := 0; j < 100; j++ {
			_, err := conn.Write(data)
			if err != nil {
				b.Fatalf("%d Unable to write: %v", j, err)
			}
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				b.Fatalf("%d Unable to read: %v", j, err)
			}
		}
		conn.Close()
	}
}
