FROM alpine:3.6
LABEL maintainer "Hiroyuki Wada <wadahiro@gmail.com>"

RUN apk add --update curl ca-certificates \
    && rm -rf /var/cache/apk/* /tmp/*

COPY bin/tproxy /usr/sbin/

COPY docker-entrypoint.sh /usr/sbin/

ENV \
    PROXY_URL="" \
    PROXY_LISTEN=":3128" \
    DNS_INTERNAL_SERVER="" \
    DNS_INTERNAL_DOMAINS="" \
    DNS_LISTEN=":53" \
    LOG_LEVEL="info"

EXPOSE 3128
EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/usr/sbin/docker-entrypoint.sh"]

