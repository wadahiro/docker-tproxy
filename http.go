package tproxy

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/elazarl/goproxy"
	"net/http"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

type HTTPProxy struct {
	HTTPProxyConfig
}

type HTTPProxyConfig struct {
	ListenAddress    string
	NoProxyAddresses []string
	NoProxyDomains   []string
}

func NewHTTPProxy(c HTTPProxyConfig) *HTTPProxy {
	return &HTTPProxy{
		HTTPProxyConfig: c,
	}
}

func (s HTTPProxy) Run() error {
	l, err := NewTCPListener(s.ListenAddress)
	if err != nil {
		log.Fatalf("Error listening for tcp connections - %s", err.Error())
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Infof("NonproxyHandler handle: %s, %s", req.Host, req.URL)
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		log.Infof("NonproxyHandler rewrite: %s, %s", req.Host, req.URL)
		proxy.ServeHTTP(w, req)
	})

	go func() {
		http.Serve(l, proxy)
	}()

	return nil
}
