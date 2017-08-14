#!/bin/sh

if [ "$PROXY_URL" = "" ]; then
    echo '[ERROR] Please set your proxy. ex) docker run -e PROXY_URL=http://foo:bar@yourproxy.example.org:81 ...'
    exit 1
fi

sed -i -e "s|@PROXY_URL@|$PROXY_URL|" /etc/transocks.toml

if [ "$DNS" != "" ]; then
    echo "[INFO] Use DNS proxy... dns: $DNS"
    # Run DNS proxy as background process
    /usr/sbin/dnsproxy -6 -dns "$DNS" &
else
    echo "[INFO] If you'd like to use DNS proxy, please set dns config. ex) docker run -e DNS=8.8.8.8:53:tcp,8.8.4.4:53:tcp,192.168.0.1:53:udp,192.168.1.1:53:udp ..."
fi

if [ "$DNS" = "" -a "$DNS_OVER_HTTPS" = "true" ]; then
    echo "[INFO] Use Google's DNS-over-HTTPS service..."
    # Run DNS-over-HTTPS proxy as background process
    export http_proxy=$PROXY_URL
    /usr/sbin/dns-over-https-proxy -address=0.0.0.0:53 &
else
    echo "[INFO] If you'd like to use Google's DNS-over-HTTPS service, please set DNS_OVER_HTTPS=true. ex) docker run -e DNS_OVER_HTTPS=true ..."
fi

if [ "$CA_URL" != "" ]; then
    echo "[INFO] Use your CA... url: $CA_URL"
    curl -L $CA_URL > /usr/share/ca-certificates/yourca.crt
    echo "yourca.crt" >> /etc/ca-certificates.conf
    update-ca-certificates
fi

# Run transparent proxy for HTTP(S)
/usr/sbin/transocks

