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

	"github.com/felixge/tcpkeepalive"
	"github.com/getlantern/golog"
	"github.com/getlantern/keyman"
	"github.com/getlantern/netx"
	"github.com/oxtoacart/bpool"
)

var (
	log = golog.LoggerFor("tlsproxy")

	mode          = flag.String("mode", "server", "Mode.  server = listen for TLS connections, client = listen for plain text connections")
	hostname      = flag.String("hostname", "", "Hostname to use for TLS. If not supplied, will auto-detect hostname")
	listenAddr    = flag.String("listen-addr", ":6380", "Address at which to listen for incoming connections")
	forwardAddr   = flag.String("forward-addr", "localhost:6379", "Address to which to forward connections")
	keepAliveIdle = flag.Duration("keepalive-idle", 2*time.Hour, "How long to wait before sending TCP keepalives")
	pkfile        = flag.String("pkfile", "pk.pem", "File containing private key for this proxy")
	certfile      = flag.String("certfile", "cert.pem", "File containing the certificate for this proxy")
	cafile        = flag.String("cafile", "cert.pem", "File containing the certificate authority (or just certificate) with which to verify the remote end's identity")
	pprofAddr     = flag.String("pprofaddr", "localhost:4000", "pprof address to listen on, not activate pprof if empty")
	help          = flag.Bool("help", false, "Get usage help")

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
	log.Debugf("Keepalive Idle: %v", *keepAliveIdle)

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
		runServer(l, *forwardAddr, *keepAliveIdle, tlsConfig)
	case "client":
		runClient(l, *forwardAddr, *keepAliveIdle, tlsConfig)
	default:
		log.Fatalf("Unknown mode: %v", *mode)
	}
}

func runServer(l net.Listener, forwardAddr string, keepAliveIdle time.Duration, tlsConfig *tls.Config) {
	doRun(tls.NewListener(wrapKeepAliveListener(keepAliveIdle, l), tlsConfig), func() (net.Conn, error) {
		return dial(keepAliveIdle, forwardAddr)
	})
}

func runClient(l net.Listener, forwardAddr string, keepAliveIdle time.Duration, tlsConfig *tls.Config) {
	host, _, err := net.SplitHostPort(forwardAddr)
	if err != nil {
		log.Fatalf("Unable to determine hostname for server: %v", err)
	}
	tlsConfig.ServerName = host
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(5000)

	doRun(wrapKeepAliveListener(keepAliveIdle, l), func() (net.Conn, error) {
		_conn, err := dial(keepAliveIdle, forwardAddr)
		if err != nil {
			return _conn, err
		}
		conn := tls.Client(_conn, tlsConfig)
		err = conn.Handshake()
		if err != nil {
			_conn.Close()
			return nil, err
		}
		if !conn.ConnectionState().DidResume {
			log.Debug("Connection did not resume")
		}
		return conn, nil
	})
}

func doRun(l net.Listener, dial func() (net.Conn, error)) {
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

func dial(keepAliveIdle time.Duration, forwardAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", forwardAddr, 30*time.Second)
	if err == nil {
		addKeepalive(keepAliveIdle, conn)
	}
	return conn, err
}

func addKeepalive(keepAliveIdle time.Duration, conn net.Conn) net.Conn {
	if keepAliveIdle <= 0 {
		return conn
	}

	c, err := tcpkeepalive.EnableKeepAlive(conn)
	if err != nil {
		log.Errorf("Unable to enable KeepAlive: %v", err)
		return conn
	}

	c.SetKeepAliveIdle(keepAliveIdle)
	c.SetKeepAliveCount(5)
	c.SetKeepAliveInterval(keepAliveIdle / 120) // works out to once a minute for a 2 hour idle

	return c
}

func wrapKeepAliveListener(keepAliveIdle time.Duration, l net.Listener) net.Listener {
	if keepAliveIdle <= 0 {
		return l
	}

	return &keepAliveListener{l: l, keepAliveIdle: keepAliveIdle}
}

type keepAliveListener struct {
	l             net.Listener
	keepAliveIdle time.Duration
}

func (l *keepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.l.Accept()
	if err == nil {
		addKeepalive(l.keepAliveIdle, conn)
	}
	return conn, err
}

func (l *keepAliveListener) Close() error {
	return l.l.Close()
}

func (l *keepAliveListener) Addr() net.Addr {
	return l.l.Addr()
}
