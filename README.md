# toxtap

Bridge Ethernet segments across all of your Tox friends into one shared Layer 2
network using a TAP interface.

## Dependencies

- [toxcore](https://github.com/TokTok/c-toxcore) (libtoxcore)
- [libsodium](https://github.com/jedisct1/libsodium)
- Linux TUN/TAP support (/dev/net/tun)

## Build

```sh
gcc -Wall -Wextra $(pkg-config --cflags toxcore libsodium) \
    main.c -o toxtap \
    $(pkg-config --libs toxcore libsodium)
```

## Usage

### Create a new Tox profile

```sh
./toxtap -n -t myprofile.tox
```

### Add a friend

```sh
./toxtap -f <tox_address_or_public_key> -t myprofile.tox
```

### Delete a friend

```sh
./toxtap -d <tox_address_or_public_key> -t myprofile.tox
```

There is no client/server distinction: both endpoints run the same daemon.

### TAP interface (created manually, not by this daemon)

The daemon never creates or configures interfaces. Create the interface as root,
assign ownership to the daemon user, and bridge it to your LAN:

```sh
sudo ip tuntap add dev toxtap0 mode tap user $(id -un)
sudo ip link set dev toxtap0 mtu 1300
sudo ip link add br0 type bridge
sudo ip link set toxtap0 master br0
sudo ip link set eth1 master br0
sudo ip link set br0 up
```

Do the same on the other endpoint. Both hosts then share one Layer 2 segment
with their LANs, so each side gets its address from the LAN's existing DHCP
server — no static addressing is configured here.

Depending on the distribution, the daemon user may also need read/write access to
`/dev/net/tun`.

### TAP daemon

```sh
./toxtap -t client.tox -i toxtap0
```

The daemon bridges the TAP interface to **all** connected friends, not a single
peer. Every Ethernet frame read from the interface is sent to every friend that
is currently online, and every frame received from a friend is written back to
the interface **and relayed to the other friends**. With friends bridged to their
own LANs, this stitches all of those segments into one shared Layer 2 network;
clients behind different friends can reach each other even when they are not
friends themselves. Friend numbers are local to each Tox profile and are only
used for display.

Friends must be added explicitly with `-f`; incoming friend requests are ignored.
Offline friends are skipped; a frame is dropped (and logged) when no friend is
reachable or every send fails.

Without duplicate suppression, use an acyclic friend topology (star or tree);
see [Duplicate suppression](#duplicate-suppression) for meshes.

Do not bridge the same physical LAN into two endpoints: that loop forms inside
the L2 bridge and is outside the daemon's control.

### Duplicate suppression

Relaying can send a frame back around a cycle in the friend graph. Enable the
duplicate cache with `-D`/`--dedup` to drop frames this node has already handled
within the last two seconds:

```sh
./toxtap -t client.tox -i toxtap0 -D
```

It is off by default. When enabled, a received frame is only remembered once the
local TAP write and the relay to every reachable friend succeeded, so a
retransmission is not mistaken for a duplicate when the first copy could not be
delivered. Locally generated frames are never entered into the cache, so
legitimate retransmissions (such as ARP retries) are never suppressed. In a graph
with a cycle, the origin segment may still receive a frame twice, but forwarding
stops there.

### Custom interface

```sh
./toxtap -t client.tox -i toxtap0
```

Use the same manual interface MTU on both endpoints. The maximum is 1358 bytes:
the Tox custom-packet limit is 1373 bytes, minus 1 byte for the tunnel prefix and
14 bytes for the Ethernet header. Larger frames are dropped and logged.

### DHCP use case

One endpoint can act as a DHCP server for hosts behind the other endpoint.
The repository ships a sample [`udhcpd.conf`](udhcpd.conf) that serves addresses
from `10.77.0.2` to `10.77.0.254` (subnet `255.255.255.0`) on `toxtap0`.

On the server side, give the TAP interface a static address from the same
subnet but outside the lease pool, then start `udhcpd`:

```sh
sudo ip tuntap add dev toxtap0 mode tap user $(id -un)
sudo ip link set dev toxtap0 mtu 1300
sudo ip addr add 10.77.0.1/24 dev toxtap0
sudo ip link set toxtap0 up
sudo udhcpd -f udhcpd.conf
./toxtap -t server.tox -i toxtap0
```

On the client side, create the TAP interface and request a lease with any
DHCP client once the tunnel is up:

```sh
sudo ip tuntap add dev toxtap0 mode tap user $(id -un)
sudo ip link set dev toxtap0 mtu 1300
sudo ip link set toxtap0 up
./toxtap -t client.tox -i toxtap0
sudo dhclient -v toxtap0   # or: sudo udhcpc -i toxtap0
```

DHCP is ordinary Ethernet broadcast/UDP, so discovery and lease replies cross
the tunnel like any other frame. Both daemons must be running and connected
before the client can get a lease. Instead of running a DHCP client on the TAP
interface itself, you can bridge `toxtap0` into a LAN (as above) and let
`udhcpd` serve that LAN's hosts.

### Lossy mode

By default frames are sent as Tox **lossless** custom packets, which is what
works reliably. To send them as **lossy** packets instead (lower latency, but
delivery is best-effort):

```sh
./toxtap -t client.tox -i toxtap0 -l
```

Either endpoint may pick its own mode; the receive path accepts packets prefixed
with either marker, so a lossy and a lossless endpoint can talk to each other.

| Mode | Flag | Prefix byte | Constant |
|---|---|---|---|
| Lossless (default) | — | 160 (`0xA0`) | `PACKET_PREFIX_LOSSLESS` |
| Lossy | `-l` | 200 (`0xC8`) | `PACKET_PREFIX_LOSSY` |

The lossy prefix is 200, not 192, because toxcore reserves lossy packet IDs
192-199 (`0xC0`-`0xC7`) for AV/RTP and silently swallows them.

## How it works

- The daemon attaches to an existing TAP interface using `TUNSETIFF`.
- Ethernet frames read from the TAP interface are sent to **every connected
  friend** as Tox custom packets with a one-byte prefix: 160 (`0xA0`) for
  lossless (default) or 200 (`0xC8`) for lossy (`-l`).
- Received frames from any friend have their prefix stripped and are written
  back to the TAP interface, where the bridge/L2 stack decides where they go.
- Each received frame is also relayed to every other connected friend, reusing
  the prefix it arrived with (lossy stays lossy, lossless stays lossless), so
  multi-hop topologies work. With `-D`, duplicate frames are suppressed by a
  two-second hash cache to keep cycles in the friend graph from looping forever;
  a frame is only recorded after a successful local write and relay.
- Frames read from the local TAP interface are only sent to the local node's
  friends; they are not marked in the duplicate cache, preserving legitimate
  L2 retransmissions.
- IP reliability is left to the protocols running inside the tunnel, such as TCP or QUIC.
