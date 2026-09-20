FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache dnsmasq

COPY dnsmasq.conf /etc/dnsmasq.conf

EXPOSE 53/udp 53/tcp

# Assigned here rather than by Compose IPAM, so 10.200.0.0/24 stays out of the
# daemon's address space and several worktrees can run the suite at once.
ENTRYPOINT ["/bin/sh", "-c", "ip addr add \"$TEST_NET_ADDR\" dev eth0 && exec dnsmasq --no-daemon --log-queries"]
