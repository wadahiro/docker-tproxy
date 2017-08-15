package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	clog "github.com/cybozu-go/log"
	"github.com/cybozu-go/transocks"
	"github.com/elazarl/goproxy"
	secop "github.com/fardog/secureoperator"
	"net"
	"net/url"
	"strings"
	//"github.com/fardog/secureoperator/cmd"
	"github.com/miekg/dns"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var (
	logLevel = flag.String(
		"logLevel",
		"info",
		"Log level, one of: debug, info, warn, error, fatal, panic",
	)

	proxyURL = flag.String(
		"proxy-url", "", "Proxy URL, like `http://user:pass@yourproxy.org`",
	)

	proxyListenAddress = flag.String(
		"proxy-listen", ":3128", "Proxy listen address, as `[host]:port`",
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
	c := transocks.NewConfig()
	c.Addr = *proxyListenAddress

	u, err := url.Parse(*proxyURL)
	if err != nil {
		log.Fatalf("Invalid proxy-url: %s", err.Error())
	}
	c.ProxyURL = u

	if err != nil {
		log.Fatalf("Invalid proxy config: %s", err.Error())
	}

	logger := clog.DefaultLogger()
	logger.SetThresholdByName(*logLevel)
	c.Logger = logger

	log.Infof("Proxy Config: %#v", c)

	serveHTTP(c)

	return []string{c.Addr}
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
