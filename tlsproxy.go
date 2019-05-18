// tlsproxy provides a TLS proxy kind of like stunnel
package tlsproxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	_ "net/http/pprof"
	"regexp"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/http-proxy/buffers"
	"github.com/getlantern/netx"
)

var log = golog.LoggerFor("tlsproxy")

func RunServer(l net.Listener, forwardAddr string, keepAlivePeriod time.Duration, tlsConfig *tls.Config, re *regexp.Regexp) {
	doRun(tls.NewListener(wrapKeepAliveListener(keepAlivePeriod, l), tlsConfig), func() (net.Conn, error) {
		return dial(keepAlivePeriod, forwardAddr)
	}, re)
}

func RunClient(l net.Listener, forwardAddr string, keepAlivePeriod time.Duration, tlsConfig *tls.Config, re *regexp.Regexp) {
	host, _, err := net.SplitHostPort(forwardAddr)
	if err != nil {
		log.Fatalf("Unable to determine hostname for server: %v", err)
	}
	tlsConfig.ServerName = host
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(5000)

	doRun(wrapKeepAliveListener(keepAlivePeriod, l), func() (net.Conn, error) {
		_conn, err := dial(keepAlivePeriod, forwardAddr)
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
	}, re)
}

func doRun(l net.Listener, dial func() (net.Conn, error), re *regexp.Regexp) {
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
			if re == nil {
				bufOut := buffers.Get()
				bufIn := buffers.Get()
				defer buffers.Put(bufOut)
				defer buffers.Put(bufIn)
				netx.BidiCopy(out, in, bufOut, bufIn)
			} else {
				go io.Copy(in, out)
				source := in.RemoteAddr().String()
				r := bufio.NewReader(in)
				for {
					b, err := r.ReadBytes('\n')
					if err != nil {
						return
					}
					if re.Match(b) {
						log.Debugf("%s from %s", string(b), source)
					}
					_, err = out.Write(b)
					if err != nil {
						return
					}
				}
			}
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
