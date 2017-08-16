package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/cybozu-go/netutil"
	"github.com/cybozu-go/transocks"
	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/wadahiro/go-tproxy"
	p "golang.org/x/net/proxy"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

var (
	logLevel = flag.String(
		"logLevel",
		"info",
		"Log level, one of: debug, info, warn, error, fatal, panic",
	)

	proxyURL = flag.String(
		"proxy-url", "", "Proxy URL, like `http://user:pass@yourproxy.org`",
	)

	proxyHttpListenAddress = flag.String(
		"proxy-http-listen", ":3128", "Proxy http listen address, as `[host]:port`",
	)

	proxyHttpsListenAddress = flag.String(
		"proxy-https-listen", ":3129", "Proxy https listen address, as `[host]:port`",
	)

	dnsListenAddress = flag.String(
		"dns-listen", ":53", "DNS listen address, as `[host]:port`",
	)

	dnsInternalServer = flag.String("dns-internal-server", "",
		"Internal DNS server where to send queries if route matched (IP[:port])")

	dnsInternalDomains = flag.String("dns-internal-domains", "",
		"List of internal subdomains where to send queries")
	dnsRoutes []string

	dnsEndpoint = flag.String(
		"dns-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP = flag.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP = flag.Bool("dns-udp", true, "DNS Listen on UDP")
)

func serveHTTP(c *transocks.Config) {
	s, err := transocks.NewServer(c)
	if err != nil {
		log.Fatal(err)
	}

	lns, _ := transocks.Listeners(c)

	for _, ln := range lns {
		s.Serve(ln)
	}

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down proxy server on interrupt\n")
}

func createProxyServer(servers chan bool) []string {
	proxyUrl, err := url.Parse(*proxyURL)
	if err != nil {
		log.Fatalf("Invalid proxy-url: %s", err.Error())
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	log.Infof("proxy.Tr, %#v", proxy.Tr)
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
		log.Fatalln(http.ListenAndServe(*proxyHttpListenAddress, proxy))
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
	pdialer, err := p.FromURL(proxyUrl, dialer)

	go func() {
		log.Infoln("Run HTTPS Listener")
		// listen to the TLS ClientHello but make it a CONNECT request instead
		ln, err := net.Listen("tcp", *proxyHttpsListenAddress)
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

	return []string{*proxyHttpListenAddress, *proxyHttpsListenAddress}
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

func main() {
	flag.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "A transparent proxy.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		flag.PrintDefaults()
	}
	flag.Parse()

	// seed the global random number generator, used in secureoperator
	rand.Seed(time.Now().UTC().UnixNano())

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", err.Error())
	}
	formatter := &log.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	}
	log.SetFormatter(formatter)
	log.SetLevel(level)

	servers := make(chan bool)

	dnsServer := tproxy.NewDNSServer(
		tproxy.DNSConfig{
			ListenAddress:   *dnsListenAddress,
			EnableUDP:       *dnsEnableUDP,
			EnableTCP:       *dnsEnableTCP,
			Endpoint:        *dnsEndpoint,
			InternalDNS:     *dnsInternalServer,
			InternalDomains: strings.Split(*dnsInternalDomains, ","),
		},
	)
	dnsServer.Run()

	createProxyServer(servers)

	log.Infoln("tproxy servers started.")

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Infoln("tproxy servers stopping.")

	// start shutdown
	dnsServer.Stop()

	log.Infoln("tproxy servers exited.")
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}
