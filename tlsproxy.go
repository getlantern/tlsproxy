// tlsproxy provides a TLS proxy kind of like stunnel
package main

import (
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/idletiming"
	"github.com/getlantern/keyman"
	"github.com/getlantern/netx"
	"github.com/oxtoacart/bpool"
)

var (
	log = golog.LoggerFor("tlsproxy")

	mode        = flag.String("mode", "server", "Mode.  server = listen for TLS connections, client = listen for plain text connections")
	hostname    = flag.String("hostname", "", "Hostname to use for TLS. If not supplied, will auto-detect hostname")
	listenAddr  = flag.String("listen-addr", ":6380", "Address at which to listen for incoming connections")
	forwardAddr = flag.String("forward-addr", "localhost:6379", "Address to which to forward connections")
	idleTimeout = flag.Duration("idletimeout", 2*time.Hour, "How long to wait before closing idle connections")
	pkfile      = flag.String("pkfile", "pk.pem", "File containing private key for this proxy")
	certfile    = flag.String("certfile", "cert.pem", "File containing the certificate for this proxy")
	cafile      = flag.String("cafile", "cert.pem", "File containing the certificate authority (or just certificate) with which to verify the remote end's identity")
	pprofAddr   = flag.String("pprofaddr", "localhost:4000", "pprof address to listen on, not activate pprof if empty")
	help        = flag.Bool("help", false, "Get usage help")

	buffers = bpool.NewBytePool(25000, 32768)
)

func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *pprofAddr != "" {
		go func() {
			log.Debugf("Starting pprof page at http://%s/debug/pprof", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Error(err)
			}
		}()
	}

	hostname := *hostname
	if hostname == "" {
		_hostname, err := os.Hostname()
		if err == nil {
			hostname = _hostname
		}
	}
	if hostname == "" {
		hostname = "localhost"
	}

	log.Debugf("Mode: %v", *mode)
	log.Debugf("Hostname: %v", hostname)
	log.Debugf("Forwarding to: %v", *forwardAddr)
	log.Debugf("Idletimeout: %v", *idleTimeout)

	cert, err := keyman.KeyPairFor(hostname, *pkfile, *certfile)
	if err != nil {
		log.Fatalf("Unable to load keypair: %v", err)
	}
	ca, err := keyman.LoadCertificateFromFile(*cafile)
	if err != nil {
		log.Fatalf("Unable to load ca certificate: %v", err)
	}
	pool := ca.PoolContainingCert()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      pool,
		ClientCAs:    pool,
	}

	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Unable to listen at %v: %v", *listenAddr, err)
	}

	switch *mode {
	case "server":
		runServer(l, *forwardAddr, *idleTimeout, tlsConfig)
	case "client":
		runClient(l, *forwardAddr, *idleTimeout, tlsConfig)
	default:
		log.Fatalf("Unknown mode: %v", *mode)
	}
}

func runServer(l net.Listener, forwardAddr string, idleTimeout time.Duration, tlsConfig *tls.Config) {
	doRun(idleTimeout, tls.NewListener(l, tlsConfig), func() (net.Conn, error) {
		return net.DialTimeout("tcp", forwardAddr, 30*time.Second)
	})
}

func runClient(l net.Listener, forwardAddr string, idleTimeout time.Duration, tlsConfig *tls.Config) {
	host, _, err := net.SplitHostPort(forwardAddr)
	if err != nil {
		log.Fatalf("Unable to determine hostname for server: %v", err)
	}
	tlsConfig.ServerName = host
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(5000)

	doRun(idleTimeout, l, func() (net.Conn, error) {
		conn, err := tls.Dial("tcp", forwardAddr, tlsConfig)
		if err == nil {
			if !conn.ConnectionState().DidResume {
				log.Debug("Connection did not resume")
			}
		}
		return conn, err
	})
}

func doRun(idleTimeout time.Duration, l net.Listener, dial func() (net.Conn, error)) {
	if idleTimeout > 0 {
		l = idletiming.Listener(l, idleTimeout, func(net.Conn) {})
	}
	defer l.Close()
	log.Debugf("Listening for incoming connections at: %v", l.Addr())

	for {
		in, err := l.Accept()
		if err != nil {
			log.Errorf("Unable to accept: %v", err)
			return
		}

		go func() {
			defer in.Close()
			out, err := dial()
			if err != nil {
				log.Debugf("Unable to dial forwarding address: %v", err)
				return
			}
			if idleTimeout > 0 {
				out = idletiming.Conn(out, idleTimeout, func() {})
			}
			defer out.Close()

			log.Debugf("Copying from %v to %v", in.RemoteAddr(), out.RemoteAddr())
			bufOut := buffers.Get()
			bufIn := buffers.Get()
			defer buffers.Put(bufOut)
			defer buffers.Put(bufIn)
			netx.BidiCopy(out, in, bufOut, bufIn)
		}()
	}
}
