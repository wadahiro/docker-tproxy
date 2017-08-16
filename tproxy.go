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
	secop "github.com/fardog/secureoperator"
	"github.com/inconshreveable/go-vhost"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	//"github.com/fardog/secureoperator/cmd"
	"github.com/miekg/dns"
	p "golang.org/x/net/proxy"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
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

	dnsNoPad = flag.Bool(
		"dns-no-pad",
		false,
		"Disable padding of Google DNS-over-HTTPS requests to identical length",
	)

	dnsEndpoint = flag.String(
		"dns-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP = flag.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP = flag.Bool("dns-udp", true, "DNS Listen on UDP")
)

func serveDNS(net string) {
	log.Infof("Starting %s service on %s", net, *dnsListenAddress)

	server := &dns.Server{Addr: *dnsListenAddress, Net: net, TsigSecret: nil}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err.Error())
		}
	}()

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Infof("Shutting down %s on interrupt\n", net)
	if err := server.Shutdown(); err != nil {
		log.Errorf("Got unexpected error %s", err.Error())
	}
}

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

func dnsProxy(addr string, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	c := &dns.Client{
		Net:     transport,
		Timeout: time.Duration(10) * time.Second,
	}
	log.Infof("DNS request. %#v, %s", req, req)
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		log.Warnf("DNS Client failed. %s, %#v, %s", err.Error(), req, req)
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}

func createDNSServer(servers chan bool) []string {
	provider, err := secop.NewGDNSProvider(*dnsEndpoint, &secop.GDNSOptions{
		Pad: !*dnsNoPad,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Internal DNS setting, %s, %s", *dnsInternalServer, *dnsInternalDomains)

	if *dnsInternalServer != "" {
		if !strings.HasSuffix(*dnsInternalServer, ":53") {
			*dnsInternalServer += ":53"
		}
	}

	if *dnsInternalDomains != "" {
		for _, s := range strings.Split(*dnsInternalDomains, ",") {
			if !strings.HasSuffix(s, ".") {
				s += "."
			}
			dnsRoutes = append(dnsRoutes, s)
		}
	}

	options := &secop.HandlerOptions{}
	handler := secop.NewHandler(provider, options)

	dnsHandle := func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			dns.HandleFailed(w, req)
			return
		}
		// Resolve by Internal DNSServer
		for _, name := range dnsRoutes {
			log.Infof("Matching DNS route,  %s : %s\n", req.Question[0].Name, name)
			if strings.HasSuffix(req.Question[0].Name, name) {
				log.Info("Matched")
				dnsProxy(*dnsInternalServer, w, req)
				return
			}
		}

		// Resolve by External DNS over HTTPS
		handler.Handle(w, req)
	}

	dns.HandleFunc(".", dnsHandle)

	var protocols []string
	if *dnsEnableTCP {
		protocols = append(protocols, "tcp")
	}
	if *dnsEnableUDP {
		protocols = append(protocols, "udp")
	}

	for _, protocol := range protocols {
		go func(protocol string) {
			serveDNS(protocol)
			servers <- true
		}(protocol)
	}

	return protocols
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

	dnsLns := createDNSServer(servers)
	proxyLns := createProxyServer(servers)

	lns := append(dnsLns, proxyLns...)

	// wait for all servers to exit
	for i := 0; i < len(lns); i++ {
		<-servers
	}

	log.Infoln("Servers exited, stopping")
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
