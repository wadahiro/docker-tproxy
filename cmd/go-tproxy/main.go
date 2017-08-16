package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/wadahiro/go-tproxy"
	"math/rand"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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

	noproxyDomains = flag.String("noproxy-domains", "",
		"List of noproxy subdomains")

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

	dnsEndpoint = flag.String(
		"dns-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP = flag.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP = flag.Bool("dns-udp", true, "DNS Listen on UDP")
)

func main() {
	flag.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "go-tproxy.\n\n")
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

	u, err := url.Parse(*proxyURL)
	if err != nil {
		log.Fatalf("Invalid proxy-url. %s", err.Error())
	}

	// start servers
	dnsServer := tproxy.NewDNSServer(
		tproxy.DNSConfig{
			ListenAddress:   *dnsListenAddress,
			EnableUDP:       *dnsEnableUDP,
			EnableTCP:       *dnsEnableTCP,
			Endpoint:        *dnsEndpoint,
			InternalDNS:     *dnsInternalServer,
			InternalDomains: strings.Split(*noproxyDomains, ","),
		},
	)
	dnsServer.Run()

	httpServer := tproxy.NewHTTPServer(
		tproxy.HTTPConfig{
			HTTPListenAddress:  *proxyHttpListenAddress,
			HTTPSListenAddress: *proxyHttpsListenAddress,
			ProxyURL:           u,
			InternalDomains:    strings.Split(*noproxyDomains, ","),
		},
	)
	if err := httpServer.Run(); err != nil {
		log.Fatalf(err.Error())
	}

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
