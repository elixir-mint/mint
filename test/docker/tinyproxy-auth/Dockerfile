FROM alpine:3.10

RUN apk add --no-cache \
	tinyproxy

RUN chown -R nobody: /home
WORKDIR /home
USER nobody

RUN mkdir -p /home/var/log/tinyproxy && mkdir -p /home/var/run/tinyproxy

COPY ./tinyproxy.conf /home/etc/tinyproxy/tinyproxy.conf

ENTRYPOINT ["tinyproxy", "-d", "-c", "/home/etc/tinyproxy/tinyproxy.conf"]
