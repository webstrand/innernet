#!/bin/bash
set -e

INNERNET_ARGS="--backend userspace"

innernet-server \
    $INNERNET_ARGS \
    new \
    --network-name "evilcorp" \
    --network-cidr "10.66.0.0/16" \
    --external-endpoint "172.18.1.1:51820" \
    --listen-port 51820

# The admin commands of innernet-server go through the running server's coordinator, so the
# first is retried until the coordinator listens.
innernet-server $INNERNET_ARGS serve evilcorp &
serve_pid=$!

for attempt in $(seq 50); do
    if innernet-server \
        $INNERNET_ARGS \
        add-cidr evilcorp \
        --name "humans" \
        --cidr "10.66.1.0/24" \
        --parent "evilcorp" \
        --yes; then
        break
    fi
    [ "$attempt" -lt 50 ] || exit 1
    sleep 0.2
done

innernet-server \
    $INNERNET_ARGS \
    add-peer evilcorp \
    --name "admin" \
    --cidr "humans" \
    --admin true \
    --auto-ip \
    --save-config "peer1.toml" \
    --invite-expires "30d" \
    --yes

wait "$serve_pid"
