package tproxy

import (
	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"os"
	"time"
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
	//pdialer := proxy.FromEnvironment()

	dialer := &net.Dialer{
		KeepAlive: 3 * time.Minute,
		DualStack: true,
	}
	u, err := url.Parse(os.Getenv("http_proxy"))
	if err != nil {
		return err
	}

	pdialer, err := proxy.FromURL(u, dialer)
	if err != nil {
		return err
	}

	log.Infof("Tcp-Proxy: Run listener on %s", s.ListenAddress)

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
