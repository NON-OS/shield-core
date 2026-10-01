#!/usr/bin/env bash
# The wallet has exactly one network destination: the proxy on loopback.
#
# This is the static half of that claim. It fails if anything outside the net
# module names a socket, a resolver or an address, so a future change cannot
# quietly open a second path out of the process. The dynamic half is a run
# against a recording proxy, which needs a device and is a separate check.
set -euo pipefail

cd "$(dirname "$0")/.."

# The socket and resolver surface of the standard library, plus the shapes a
# url or an address takes in source.
patterns='TcpStream|TcpListener|UdpSocket|UnixStream|to_socket_addrs|SocketAddr|lookup_host|https?://'

# What is scanned is exactly what a phone runs.
offenders=$(grep -rnE "$patterns" core/src field-kernel/src \
    --include='*.rs' | grep -v '^core/src/net/' || true)

if [ -n "$offenders" ]; then
    echo "network surface outside core/src/net, in code that ships:" >&2
    echo "$offenders" >&2
    exit 1
fi

# And inside the net module, exactly one place may connect.
connects=$(grep -rn "TcpStream::connect" core/src/net --include='*.rs' | wc -l | tr -d ' ')
if [ "$connects" != "1" ]; then
    echo "expected exactly one TcpStream::connect in the net module, found $connects" >&2
    exit 1
fi

echo "one destination: the proxy, reached from core/src/net/socks5/connect.rs"
