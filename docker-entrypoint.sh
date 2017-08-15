#!/bin/sh

if [ "$PROXY_URL" = "" ]; then
    echo '[ERROR] Please set your proxy. ex) docker run -e PROXY_URL=http://foo:bar@yourproxy.example.org:81 ...'
    exit 1
fi

export http_proxy=$PROXY_URL

if [ "$CA_URL" != "" ]; then
    echo "[INFO] Use your CA... url: $CA_URL"
    curl -L $CA_URL > /usr/share/ca-certificates/yourca.crt
    echo "yourca.crt" >> /etc/ca-certificates.conf
    update-ca-certificates
fi

# Run transparent proxy
/usr/sbin/tproxy \
    -proxy-url "$PROXY_URL" \
    -proxy-listen "$PROXY_LISTEN" \
    -dns-listen "$DNS_LISTEN" \
    -dns-internal-server "$DNS_INTERNAL_SERVER" \
    -dns-internal-domains "$DNS_INTERNAL_DOMAINS" \
    -logLevel "$LOG_LEVEL"

