package tproxy

import (
	log "github.com/Sirupsen/logrus"
	secop "github.com/fardog/secureoperator"
	"github.com/miekg/dns"
	"net"
	"strings"
	"sync"
	"time"
)

type DNSServer struct {
	DNSConfig
	udpServer *dns.Server
	tcpServer *dns.Server
	udpClient *dns.Client // used for fowarding to internal DNS
	tcpClient *dns.Client // used for fowarding to internal DNS
	waitGroup *sync.WaitGroup
}

type DNSConfig struct {
	ListenAddress   string
	EnableUDP       bool
	EnableTCP       bool
	Endpoint        string
	InternalDNS     string
	InternalDomains []string
}

func NewDNSServer(c DNSConfig) *DNSServer {

	// fix internal dns address
	if c.InternalDNS != "" {
		if !strings.HasSuffix(c.InternalDNS, ":53") {
			c.InternalDNS += ":53"
		}
	}

	// fix domains
	var dnsRoutes []string
	for _, s := range c.InternalDomains {
		if !strings.HasSuffix(s, ".") {
			s += "."
		}
		dnsRoutes = append(dnsRoutes, s)
	}
	c.InternalDomains = dnsRoutes

	return &DNSServer{
		DNSConfig: c,
		udpServer: nil,
		tcpServer: nil,
		udpClient: &dns.Client{
			Net:            "udp",
			Timeout:        time.Duration(10) * time.Second,
			SingleInflight: true,
		},
		tcpClient: &dns.Client{
			Net:            "tcp",
			Timeout:        time.Duration(10) * time.Second,
			SingleInflight: true,
		},
		waitGroup: new(sync.WaitGroup),
	}
}

func (s *DNSServer) Run() error {
	log.Infof("Starting DNS service on %s", s.ListenAddress)
	log.Infof("Internal DNS setting, %s, %s", s.InternalDNS, s.InternalDomains)

	// Prepare external DNS handler
	provider, err := secop.NewGDNSProvider(s.Endpoint, &secop.GDNSOptions{
		Pad: true,
	})

	if err != nil {
		log.Fatal(err)
	}

	options := &secop.HandlerOptions{}
	externalHandler := secop.NewHandler(provider, options)

	// Setup DNS Handler
	dnsHandle := func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			dns.HandleFailed(w, req)
			return
		}
		// Resolve by Internal DNSServer
		for _, domain := range s.InternalDomains {
			log.Infof("Matching DNS route,  %s : %s\n", req.Question[0].Name, domain)
			if strings.HasSuffix(req.Question[0].Name, domain) {
				log.Info("Matched! Routing to internal DNS")
				s.handleInternal(w, req)
				return
			}
		}

		// Resolve by External DNS over HTTPS
		externalHandler.Handle(w, req)
	}

	dns.HandleFunc(".", dnsHandle)

	// Start DNS Server

	if s.EnableUDP {
		s.udpServer = &dns.Server{
			Addr:       s.ListenAddress,
			Net:        "udp",
			TsigSecret: nil,
		}
	}
	if s.EnableTCP {
		s.tcpServer = &dns.Server{
			Addr:       s.ListenAddress,
			Net:        "tcp",
			TsigSecret: nil,
		}
	}

	go func() {
		if s.udpServer != nil {
			if err := s.udpServer.ListenAndServe(); err != nil {
				log.Fatal(err.Error())
			}
		}
		if s.tcpServer != nil {
			if err := s.tcpServer.ListenAndServe(); err != nil {
				log.Fatal(err.Error())
			}
		}
	}()

	return nil
}

func (s *DNSServer) handleInternal(w dns.ResponseWriter, req *dns.Msg) {
	var c *dns.Client
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		c = s.tcpClient
	} else {
		c = s.udpClient
	}

	log.Infof("DNS request. %#v, %s", req, req)

	resp, _, err := c.Exchange(req, s.InternalDNS)
	if err != nil {
		log.Warnf("DNS Client failed. %s, %#v, %s", err.Error(), req, req)
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}

func (s *DNSServer) Stop() {
	log.Infof("Shutting down DNS service on interrupt\n")

	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			log.Error(err.Error())
		}
		s.udpServer = nil
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			log.Error(err.Error())
		}
		s.tcpServer = nil
	}
}
