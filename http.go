package tproxy

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/cybozu-go/netutil"
	_ "github.com/cybozu-go/transocks"
	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	p "golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

type HTTPServer struct {
	HTTPConfig
}

type HTTPConfig struct {
	HTTPListenAddress  string
	HTTPSListenAddress string
	ProxyURL           *url.URL
	InternalDomains    []string
}

func NewHTTPServer(c HTTPConfig) *HTTPServer {
	return &HTTPServer{
		HTTPConfig: c,
	}
}

func (s HTTPServer) Run() error {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.ConnectDial = nil

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Infof("NonproxyHandler handle: %s, %#v", req.Host, req.URL)
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile(".*"))).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			log.Infof("HijackConnect: %s, %#v", req.Host, req.URL)
			defer func() {
				if e := recover(); e != nil {
					ctx.Logf("error connecting to remote: %v", e)
					client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				}
				client.Close()
			}()
		})

	go func() {
		log.Fatalln(http.ListenAndServe(s.HTTPListenAddress, proxy))
	}()

	pool := sync.Pool{
		New: func() interface{} {
			return make([]byte, 64<<10)
		},
	}
	dialer := &net.Dialer{
		KeepAlive: 3 * time.Minute,
		DualStack: true,
	}
	pdialer, err := p.FromURL(s.ProxyURL, dialer)
	if err != nil {
		return err
	}

	go func() {
		log.Infoln("Run HTTPS Listener")
		// listen to the TLS ClientHello but make it a CONNECT request instead
		ln, err := net.Listen("tcp", s.HTTPSListenAddress)
		if err != nil {
			log.Fatalf("Error listening for https connections - %v", err)
		}
		for {
			c, err := ln.Accept()
			log.Infoln("Accepted HTTPS connection")
			if err != nil {
				log.Printf("Error accepting new connection - %v", err)
				continue
			}
			go func(c net.Conn) {
				tlsConn, err := vhost.TLS(c)
				if err != nil {
					log.Printf("Error accepting new connection - %v", err)
				}

				defer func() {
					tlsConn.Free()
				}()

				dest := tlsConn.Host()
				if dest == "" {
					log.Printf("Cannot support non-SNI enabled clients")
					return
				}

				log.Infof("Proxy to %s", dest)

				handleConnection(c, pool, pdialer, dest, tlsConn.ClientHelloMsg.Raw)
			}(c)
		}
	}()

	return nil
}

func handleConnection(conn net.Conn, pool sync.Pool, dialer p.Dialer, addr string, clientHello []byte) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		log.Error("non-TCP connection", map[string]interface{}{
			"conn": conn,
		})
		return
	}

	destConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		log.Error("failed to connect to proxy server")
		return
	}
	defer destConn.Close()

	log.Info("proxy starts")

	wg := &sync.WaitGroup{}

	log.Infof("send clientHello start %d", len(clientHello))

	length := len(clientHello)

	header := []byte{0x16, 0x03, 0x01, byte(length >> 8), byte(length)}

	record := append(header, clientHello...)

	destConn.Write(record)

	log.Info("send clientHello over proxy")

	// do proxy
	wg.Add(1)
	go func() error {
		defer func() {
			wg.Done()
		}()

		buf := pool.Get().([]byte)
		_, err := io.CopyBuffer(destConn, tc, buf)
		pool.Put(buf)
		if hc, ok := destConn.(netutil.HalfCloser); ok {
			hc.CloseWrite()
		}
		tc.CloseRead()
		return err
	}()

	wg.Add(1)
	go func() error {
		defer func() {
			wg.Done()
		}()

		buf := pool.Get().([]byte)
		_, err := io.CopyBuffer(tc, destConn, buf)
		pool.Put(buf)
		tc.CloseWrite()
		if hc, ok := destConn.(netutil.HalfCloser); ok {
			hc.CloseRead()
		}
		return err
	}()

	wg.Wait()

	log.Info("proxy ends")
}
