package main

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/getlantern/fdcount"
	"github.com/getlantern/keyman"
	"github.com/stretchr/testify/assert"
)

const (
	iters      = 100
	checkDelay = 2 * time.Second
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

	_, fdc, err := fdcount.Matching("TCP")
	if !assert.NoError(t, err) {
		return
	}
	go runServer(sl, l.Addr().String(), 0*time.Millisecond, serverConfig)
	go runClient(cl, sl.Addr().String(), 0*time.Millisecond, clientConfig)

	// execute client code in a separate process to make sure we handle unclean
	// disconnect well (using keepalives)
	wd, err := os.Getwd()
	if !assert.NoError(t, err) {
		return
	}

	// the below is a little convoluted, but we need to first compile the test
	// client and then run it with ForkExec so that it actually terminates before
	// the test program itself.
	err = exec.Command("go", "build", "-o", "tclient", "testclient/testclient.go").Run()
	if !assert.NoError(t, err) {
		return
	}
	testClientPID, err := syscall.ForkExec(filepath.Join(wd, "tclient"), []string{filepath.Join(wd, "testclient/testclient.go"), cl.Addr().String(), strconv.Itoa(iters)}, nil)
	if !assert.NoError(t, err) {
		return
	}

	// wait a little bit and then kill the client
	time.Sleep(checkDelay)
	err = syscall.Kill(testClientPID, syscall.SIGKILL)
	if !assert.NoError(t, err) {
		return
	}
	log.Debug("Killed child process")

	time.Sleep(checkDelay)

	assert.NoError(t, fdc.AssertDelta(0))
}
