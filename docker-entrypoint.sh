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
    echo "[WARN] If you'd like to use DNS proxy, please set dns config. ex) docker run -e DNS=8.8.8.8:53:tcp,8.8.4.4:53:tcp,192.168.0.1:53:udp,192.168.1.1:53:udp ..."
fi

# Run transparent proxy for HTTP(S)
/usr/sbin/transocks

