FROM alpine
LABEL maintainer "Hiroyuki Wada <wadahiro@gmail.com>"

RUN apk add --update curl ca-certificates \
    && rm -rf /var/cache/apk/* /tmp/*

COPY bin/transocks /usr/sbin/
COPY bin/dnsproxy /usr/sbin/
COPY bin/dns-over-https-proxy /usr/sbin/

COPY transocks.toml /etc/

COPY docker-entrypoint.sh /usr/sbin/

EXPOSE 3128
EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/usr/sbin/docker-entrypoint.sh"]

