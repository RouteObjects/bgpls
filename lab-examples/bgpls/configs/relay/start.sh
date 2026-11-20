#!/bin/sh
set -eu

#  Containerlab creates data-plane interfaces after starting Linux nodes.
# Bound this wait so a broken topology fails instead of hanging indefinitely.
attempt=0
while [ ! -e /sys/class/net/eth1 ]; do
    if [ "$attempt" -ge 30 ]; then
        echo "bgpls-relay: eth1 did not appear within 30 seconds" >&2
        exit 1
    fi
    sleep 1
    attempt=$((attempt + 1))
done

ip address replace 10.254.254.1/31 dev eth1
ip link set eth1 up
# Validate configuration before opening the TCP listener.
haproxy -c -f /etc/bgpls-relay/haproxy.cfg
exec haproxy -W -db -f /etc/bgpls-relay/haproxy.cfg
