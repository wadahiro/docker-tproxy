FROM alpine
LABEL maintainer "Hiroyuki Wada <wadahiro@gmail.com>"

COPY bin/transocks /usr/sbin/
COPY bin/dnsproxy /usr/sbin/

COPY transocks.toml /etc/

COPY docker-entrypoint.sh /usr/sbin/

EXPOSE 3128
EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/usr/sbin/docker-entrypoint.sh"]

