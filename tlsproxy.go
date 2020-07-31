// Package tlsproxy provides a TLS proxy kind of like stunnel
package tlsproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/getlantern/http-proxy/buffers"
	"github.com/getlantern/netx"
	"github.com/siddontang/go/log"
)

// RunServer starts a TLS server proxy. This proxy expects TLS connections and forwards the wrapped
// data to the specified address.
func RunServer(l net.Listener, forwardAddr string, keepAlivePeriod time.Duration, tlsConfig *tls.Config) {
	dialFn := func() (net.Conn, error) { return dial(keepAlivePeriod, stripScheme(forwardAddr)) }
	doRun(tls.NewListener(wrapKeepAliveListener(keepAlivePeriod, l), tlsConfig), dialFn, getProtocol(forwardAddr))
}

// RunClient starts a TLS client proxy. This proxy expects plaintext connections and wraps the data
// in a TLS connection to forward it to the specified address.
func RunClient(l net.Listener, forwardAddr string, keepAlivePeriod time.Duration, tlsConfig *tls.Config) {
	host, _, err := net.SplitHostPort(stripScheme(forwardAddr))
	if err != nil {
		log.Fatalf("Unable to determine hostname for server: %v", err)
	}
	tlsConfig.ServerName = host
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(5000)

	dialFn := func() (net.Conn, error) {
		_conn, err := dial(keepAlivePeriod, stripScheme(forwardAddr))
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
	}
	doRun(wrapKeepAliveListener(keepAlivePeriod, l), dialFn, getProtocol(forwardAddr))
}

func doRun(l net.Listener, dial func() (net.Conn, error), forwardProtocol protocol) {
	defer l.Close()
	log.Debugf("Listening for incoming connections at: %v", l.Addr())

	for {
		in, err := l.Accept()
		if err != nil {
			return
		}

		go func() {
			defer in.Close()
			out, err := dial()
			if err != nil {
				log.Debugf("Unable to dial forwarding address: %v", err)
				if err := forwardProtocol.writeBadGateway(in); err != nil {
					log.Debugf("failed to respond with Bad Gateway: %w", err)
				}
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

func dial(keepAlivePeriod time.Duration, forwardAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", forwardAddr, 30*time.Second)
	if err == nil && keepAlivePeriod > 0 {
		addKeepalive(keepAlivePeriod, conn)
	}
	return conn, err
}

func addKeepalive(keepAlivePeriod time.Duration, conn net.Conn) {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		log.Error("Conn was not a TCPConn, can't set KeepAlivePeriod!")
		return
	}
	err := c.SetKeepAlive(true)
	if err != nil {
		log.Errorf("Unable to turn on TCP keep alives: %v", err)
		return
	}
	err = c.SetKeepAlivePeriod(keepAlivePeriod)
	if err != nil {
		log.Errorf("Unable to set KeepAlivePeriod: %v", err)
	}
}

func wrapKeepAliveListener(keepAlivePeriod time.Duration, l net.Listener) net.Listener {
	if keepAlivePeriod <= 0 {
		return l
	}

	return &keepAliveListener{l: l, keepAlivePeriod: keepAlivePeriod}
}

type keepAliveListener struct {
	l               net.Listener
	keepAlivePeriod time.Duration
}

func (l *keepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.l.Accept()
	if err == nil {
		addKeepalive(l.keepAlivePeriod, conn)
	}
	return conn, err
}

func (l *keepAliveListener) Close() error {
	return l.l.Close()
}

func (l *keepAliveListener) Addr() net.Addr {
	return l.l.Addr()
}

func stripScheme(addr string) string {
	splits := strings.Split(addr, "://")
	if len(splits) == 1 {
		return splits[0]
	}
	return splits[1]
}

type protocol interface {
	name() string
	writeBadGateway(io.Writer) error
}

type protocolHTTP struct{}

func (p protocolHTTP) name() string { return "HTTP" }

func (p protocolHTTP) writeBadGateway(w io.Writer) error {
	return (&http.Response{
		StatusCode:    http.StatusBadGateway,
		ProtoMajor:    1,
		ContentLength: -1,
	}).Write(w)
}

// REdis Serialization Protocol: https://redis.io/topics/protocol
type protocolRESP struct{}

func (p protocolRESP) name() string { return "RESP" }

func (p protocolRESP) writeBadGateway(w io.Writer) error {
	_, err := w.Write([]byte("-ERR bad gateway\r\n"))
	return err
}

type protocolUnknown string

func (p protocolUnknown) name() string { return string(p) }

func (p protocolUnknown) writeBadGateway(_ io.Writer) error {
	return fmt.Errorf("unknown protocol '%s'", p)
}

func getProtocol(addr string) protocol {
	if !strings.Contains(addr, "://") {
		return protocolHTTP{}
	}
	protocolName := strings.Split(addr, "://")[0]
	switch protocolName {
	case "http":
		return protocolHTTP{}
	case "resp":
		return protocolRESP{}
	default:
		return protocolUnknown(protocolName)
	}
}
