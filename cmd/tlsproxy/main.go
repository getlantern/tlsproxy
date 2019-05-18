package main

import (
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"regexp"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/keyman"
	"github.com/oxtoacart/bpool"

	"github.com/getlantern/tlsproxy"
)

var (
	log = golog.LoggerFor("tlsproxy")

	mode            = flag.String("mode", "server", "Mode.  server = listen for TLS connections, client = listen for plain text connections")
	hostname        = flag.String("hostname", "", "Hostname to use for TLS. If not supplied, will auto-detect hostname")
	listenAddr      = flag.String("listen-addr", ":6380", "Address at which to listen for incoming connections")
	forwardAddr     = flag.String("forward-addr", "localhost:6379", "Address to which to forward connections")
	keepAlivePeriod = flag.Duration("keepaliveperiod", 2*time.Hour, "Period for sending tcp keepalives")
	pkfile          = flag.String("pkfile", "pk.pem", "File containing private key for this proxy")
	certfile        = flag.String("certfile", "cert.pem", "File containing the certificate for this proxy")
	cafile          = flag.String("cafile", "cert.pem", "File containing the certificate authority (or just certificate) with which to verify the remote end's identity")
	pprofAddr       = flag.String("pprofaddr", "localhost:4000", "pprof address to listen on, not activate pprof if empty")
	printIfMatch    = flag.String("printifmatch", "", "Print the source IP and port if the line matches the given regex. Affects performance. Not doing match if empty.")
	help            = flag.Bool("help", false, "Get usage help")

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
	log.Debugf("TCP KeepAlive Period: %v", *keepAlivePeriod)

	cert, err := keyman.KeyPairFor(hostname, "getlantern.org", *pkfile, *certfile)
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

	var re *regexp.Regexp
	if *printIfMatch != "" {
		re = regexp.MustCompile(*printIfMatch)
	}

	switch *mode {
	case "server":
		tlsproxy.RunServer(l, *forwardAddr, *keepAlivePeriod, tlsConfig, re)
	case "client":
		tlsproxy.RunClient(l, *forwardAddr, *keepAlivePeriod, tlsConfig, re)
	default:
		log.Fatalf("Unknown mode: %v", *mode)
	}
}
