package tproxy

import (
	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/proxy"
)

type TCPProxy struct {
	TCPProxyConfig
}

type TCPProxyConfig struct {
	ListenAddress    string
	NoProxyAddresses []string
	NoProxyDomains   []string
}

func NewTCPProxy(c TCPProxyConfig) *TCPProxy {
	return &TCPProxy{
		TCPProxyConfig: c,
	}
}

func (s TCPProxy) Run() error {
	pdialer := proxy.FromEnvironment()

	log.Infoln("TCP-Proxy: Run listener")

	go func() {
		ListenTCP(s.ListenAddress, func(tc *TCPConn) {
			destConn, err := pdialer.Dial("tcp", tc.OrigAddr)
			if err != nil {
				log.Errorf("TCP-Proxy: Failed to connect to destination - %s", err.Error())
				return
			}

			Pipe(tc, destConn)
		})
	}()

	return nil
}
