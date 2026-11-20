#!/bin/sh
set -eu

#  Both dedicated collector links must exist before either listener opens.
for interface in eth1 eth2; do
    attempt=0
    while [ ! -e "/sys/class/net/$interface" ]; do
        if [ "$attempt" -ge 30 ]; then
            echo "bgpls-relay: $interface did not appear within 30 seconds" >&2
            exit 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
done
ip address replace 10.254.254.1/31 dev eth1
ip link set eth1 up
ip address replace 10.254.254.3/31 dev eth2
ip link set eth2 up
haproxy -c -f /etc/bgpls-relay/haproxy.cfg
exec haproxy -W -db -f /etc/bgpls-relay/haproxy.cfg
