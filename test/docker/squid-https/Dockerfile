FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends squid-openssl openssl && \
    rm -rf /var/lib/apt/lists/*

# Self-signed certificate for the TLS listener. Tests connect to the proxy
# with verify: :verify_none.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout /etc/squid/key.pem -out /etc/squid/cert.pem -subj "/CN=localhost"

COPY squid.conf /etc/squid/squid.conf

EXPOSE 3129

CMD ["squid", "-N", "-d", "1"]
