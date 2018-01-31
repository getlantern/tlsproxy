package tlsproxy

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/getlantern/keyman"
	"github.com/stretchr/testify/assert"
)

const (
	iters = 100
)

var (
	data = []byte("Hello there strange and wonderful benchmarking world!")
)

func TestProxy(t *testing.T) {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pk.TLSCertificateFor(time.Now().Add(24*time.Hour), false, nil, "lantern", "lantern")
	if err != nil {
		t.Fatal(err)
	}
	keyPair, err := tls.X509KeyPair(cert.PEMEncoded(), pk.PEMEncoded())
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
	}
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	defer sl.Close()

	cl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	go RunServer(sl, l.Addr().String(), 150*time.Millisecond, serverConfig)
	go RunClient(cl, sl.Addr().String(), 150*time.Millisecond, clientConfig)

	clientAddr := cl.Addr().String()

	conn, err := net.Dial("tcp", clientAddr)
	if err != nil {
		t.Fatalf("Unable to dial client proxy: %v", err)
	}
	defer conn.Close()

	// Write
	go func() {
		for j := 0; j < iters; j++ {
			_, err := conn.Write(data)
			if err != nil {
				t.Fatalf("%d Unable to write: %v", j, err)
			}
		}
	}()

	// Read (should stop automatically due to TCP keepalive)
	buf := make([]byte, len(data))
	for i := 0; i < iters; i++ {
		_, err := io.ReadFull(conn, buf)
		if !assert.NoError(t, err) {
			return
		}
	}
}
