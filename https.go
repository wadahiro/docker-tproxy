package tproxy

import (
	log "github.com/Sirupsen/logrus"
	"github.com/inconshreveable/go-vhost"
	"golang.org/x/net/proxy"
	"net"
)

type HTTPSProxy struct {
	HTTPSProxyConfig
}

type HTTPSProxyConfig struct {
	ListenAddress    string
	NoProxyDomains   []string
	NoProxyAddresses []string
}

func NewHTTPSProxy(c HTTPSProxyConfig) *HTTPSProxy {
	return &HTTPSProxy{
		HTTPSProxyConfig: c,
	}
}

func (s HTTPSProxy) Run() error {
	pdialer := proxy.FromEnvironment()

	log.Infoln("HTTPS-Proxy: Run listener")

	go func() {
		ListenTCP(s.ListenAddress, func(tc *TCPConn) {
			tlsConn, err := vhost.TLS(tc)
			if err != nil {
				log.Errorf("HTTPS-Proxy: Error handling TLS connection - %s", err.Error())
				return
			}

			defer func() {
				tlsConn.Free()
			}()

			origServer := tlsConn.Host()
			if origServer == "" {
				log.Warn("HTTPS-Proxy: Cannot get SNI, so fallback using `SO_ORIGINAL_DST` or `IP6T_SO_ORIGINAL_DST`")
				origServer = tc.OrigAddr

				// TODO getting domain from origAddr, then check whether we should use proxy or not
			} else {
				log.Infof("HTTPS-Proxy: SNI: %s", origServer)
				origServer = net.JoinHostPort(origServer, "443")
			}

			destConn, err := pdialer.Dial("tcp", origServer)
			if err != nil {
				log.Errorf("HTTPS-Proxy: Failed to connect to destination - %s", err.Error())
				return
			}

			// First, write ClientHello to real destination because we have already read it
			ch := tlsConn.ClientHelloMsg.Raw
			chSize := len(ch)
			chHeader := []byte{0x16, 0x03, 0x01, byte(chSize >> 8), byte(chSize)}
			chRecord := append(chHeader, ch...)
			destConn.Write(chRecord)

			// Then, pipe the data
			Pipe(tc, destConn)
		})
	}()

	return nil
}
