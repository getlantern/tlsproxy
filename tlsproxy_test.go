package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/getlantern/keyman"
	"github.com/stretchr/testify/assert"
)

const (
	iters = 100
)

func TestProxy(t *testing.T) {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pk.TLSCertificateFor("lantern", "lantern", time.Now().Add(24*time.Hour), false, nil)
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

	go runServer(sl, l.Addr().String(), 150*time.Millisecond, serverConfig)
	go runClient(cl, sl.Addr().String(), 150*time.Millisecond, clientConfig)

	// execute client code in a separate process to make sure we handle unclean
	// disconnect well (using keepalives)
	testClient := exec.Command("go", "run", "testclient/testclient.go", cl.Addr().String(), strconv.Itoa(iters))
	go func() {
		// forcibly kill test client after waiting a little bit
		time.Sleep(2 * time.Second)
		testClient.Process.Kill()
	}()

	out, err := testClient.CombinedOutput()
	if !assert.NoError(t, err) {
		return
	}
	fmt.Println(out)
}
