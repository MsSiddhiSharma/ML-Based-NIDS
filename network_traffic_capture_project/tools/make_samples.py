#!/usr/bin/env python3
"""
make_samples.py - Build synthetic sample PCAP files for testing packet_capture.py.

All traffic is fabricated (RFC 1918 / documentation addresses), so the samples
are safe to share. Each file is described in samples/README.txt together with
the exact packet counts the parser is expected to report.

Run:  python3 make_samples.py            (writes into ./samples)
"""

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packet_capture import write_pcap   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "samples")
T0 = 1_761_600_000.0          # fixed epoch so output is reproducible (Oct 2025)

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
MAC_GW = bytes.fromhex("0200000000fe")


# ------------------------------- builders ---------------------------------- #

def ip_checksum(hdr: bytes) -> int:
    if len(hdr) % 2:
        hdr += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(hdr) // 2), hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64, ident=1, flags_frag=0, ihl_words=5,
         total_len=None):
    options = b"\x00" * ((ihl_words - 5) * 4) if ihl_words > 5 else b""
    tl = total_len if total_len is not None else (ihl_words * 4 + len(payload))
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl_words, 0, tl, ident,
                      flags_frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst)) + options
    csum = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, flags, payload=b"", seq=1000, ack=0):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                       65535, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(payload=b"abcdefgh", typ=8):
    return struct.pack("!BBHHH", typ, 0, 0, 0x1234, 1) + payload


def eth(dst, src, ethertype, payload):
    return dst + src + struct.pack("!H", ethertype) + payload


def vlan_eth(dst, src, vid, inner_type, payload):
    return dst + src + struct.pack("!HHH", 0x8100, vid, inner_type) + payload


def ipv6(src, dst, nxt, payload, hop=64):
    return (struct.pack("!IHBB", 6 << 28, len(payload), nxt, hop)
            + socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst) + payload)


def arp_request(sender_ip, target_ip):
    return (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + MAC_A
            + socket.inet_aton(sender_ip) + b"\x00" * 6
            + socket.inet_aton(target_ip))


def dns_query(name="example.com"):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


# ------------------------------ sample sets -------------------------------- #

def normal_packets():
    c, s, dns = "192.168.1.10", "93.184.216.34", "192.168.1.1"
    pk = []
    t = T0
    def add(frame, dt=0.01):
        nonlocal t
        pk.append((t, len(frame), frame))
        t += dt
    # 1 ARP who-has
    add(eth(b"\xff" * 6, MAC_A, 0x0806, arp_request(c, "192.168.1.1")))
    # 2-3 DNS query + response
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, dns, 17, udp(53211, 53, dns_query()))))
    add(eth(MAC_A, MAC_GW, 0x0800, ipv4(dns, c, 17, udp(53, 53211, b"\x00" * 48))))
    # 4-6 TCP handshake
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 6, tcp(40000, 80, 0x02))))
    add(eth(MAC_A, MAC_GW, 0x0800, ipv4(s, c, 6, tcp(80, 40000, 0x12, ack=1001))))
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 6, tcp(40000, 80, 0x10, ack=1))))
    # 7-8 HTTP request / response
    req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 6, tcp(40000, 80, 0x18, req))))
    add(eth(MAC_A, MAC_GW, 0x0800, ipv4(s, c, 6, tcp(80, 40000, 0x18, b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 200))))
    # 9-10 ICMP echo request / reply
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, "8.8.8.8", 1, icmp_echo())))
    add(eth(MAC_A, MAC_GW, 0x0800, ipv4("8.8.8.8", c, 1, icmp_echo(typ=0))))
    # 11 HTTPS SYN
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, "151.101.1.69", 6, tcp(40001, 443, 0x02))))
    # 12 VLAN-tagged TCP (SSH)
    add(vlan_eth(MAC_B, MAC_A, 100, 0x0800,
                 ipv4("10.0.0.5", "10.0.0.9", 6, tcp(51000, 22, 0x10))))
    # 13 IPv6 UDP
    add(eth(MAC_B, MAC_A, 0x86DD,
            ipv6("2001:db8::1", "2001:db8::2", 17, udp(5000, 5001, b"hello6"))))
    # 14 IPv6 ICMPv6 (no ports)
    add(eth(MAC_B, MAC_A, 0x86DD,
            ipv6("fe80::1", "ff02::1", 58, struct.pack("!BBH", 128, 0, 0) + b"\x00" * 4)))
    # 15 TCP FIN/ACK
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 6, tcp(40000, 80, 0x11, ack=2))))
    # 16 UDP syslog to 10.0.0.9
    add(eth(MAC_B, MAC_A, 0x0800, ipv4("10.0.0.5", "10.0.0.9", 17, udp(40514, 514, b"<13>test message"))))
    return pk


def malformed_packets():
    c, s = "192.168.1.10", "93.184.216.34"
    good = lambda sp, dp: eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 6, tcp(sp, dp, 0x10)))
    pk = []
    t = T0
    def add(frame, dt=0.01, orig=None, ts=None):
        nonlocal t
        pk.append((t if ts is None else ts, len(frame) if orig is None else orig, frame))
        t += dt
    add(good(40000, 80))                                       # 1  ok
    add(b"")                                                   # 2  empty packet
    add(b"\x01\x02\x03\x04\x05")                               # 3  5-byte frame (truncated Ethernet)
    add(eth(MAC_GW, MAC_A, 0x0800, b"\x45\x00\x00\x28\x00\x01"))   # 4 truncated IPv4 header
    bad_ihl = bytearray(ipv4(c, s, 6, tcp(1234, 80, 0x02)))
    bad_ihl[0] = 0x43                                          # version 4, IHL=3 (12 bytes) -> invalid
    add(eth(MAC_GW, MAC_A, 0x0800, bytes(bad_ihl)))            # 5  invalid IHL
    # 6 IP says 1500 bytes but only the headers were captured (snaplen-style truncation)
    pkt = ipv4(c, s, 6, tcp(5555, 443, 0x18, b"A" * 20), total_len=1500)
    add(eth(MAC_GW, MAC_A, 0x0800, pkt), orig=1514)
    # 7 TCP header cut after 2 bytes (ports incomplete)
    full = eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 6, tcp(6000, 8080, 0x02)))
    add(full[:14 + 20 + 2], orig=len(full))
    # 8 TCP header cut after ports but before flags
    add(full[:14 + 20 + 6], orig=len(full))
    # 9 unknown EtherType (LLDP 0x88cc)
    add(eth(b"\x01\x80\xc2\x00\x00\x0e", MAC_A, 0x88CC, b"\x02\x07\x04" + b"\x00" * 20))
    # 10 non-first IPv4 fragment (no ports)
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 17, b"\x00" * 32, flags_frag=0x00B9)))
    # 11 valid packet but bogus timestamp fraction (set below)
    add(good(40002, 22))                                       # usec field patched after write
    # 12 IPv6 header cut short
    v6 = eth(MAC_B, MAC_A, 0x86DD, ipv6("2001:db8::1", "2001:db8::2", 17, udp(1, 2)))
    add(v6[:14 + 25], orig=len(v6))
    # 13 unknown IP protocol number
    add(eth(MAC_GW, MAC_A, 0x0800, ipv4(c, s, 253, b"\x00" * 8)))
    # 14 captured length bigger than original length
    add(good(40003, 25), orig=20)
    # 15 truncated ARP
    add(eth(b"\xff" * 6, MAC_A, 0x0806, arp_request(c, "192.168.1.1")[:10]))
    # 16 ok again, so we prove parsing recovers after bad packets
    add(good(40004, 8443))
    return pk


def write_raw_ip(path):
    pk = []
    t = T0
    for i in range(3):
        pk.append((t + i, 0, ipv4("10.1.1.1", "10.1.1.2", 6, tcp(2000 + i, 9000, 0x02))))
    pk.append((t + 3, 0, ipv4("10.1.1.1", "10.1.1.2", 17, udp(3000, 3001, b"raw"))))
    pk = [(ts, len(d), d) for ts, _, d in pk]
    write_pcap(path, pk, link_type=101)


def write_sll(path):
    def sll(inner, ethertype=0x0800):
        return struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\x00\x00", ethertype) + inner
    pk = []
    pk.append((T0, 0, sll(ipv4("172.16.0.2", "172.16.0.9", 6, tcp(33000, 3306, 0x02)))))
    pk.append((T0 + 1, 0, sll(ipv4("172.16.0.9", "172.16.0.2", 6, tcp(3306, 33000, 0x12)))))
    pk.append((T0 + 2, 0, sll(ipv4("172.16.0.2", "172.16.0.9", 17, udp(123, 123, b"\x1b" + b"\x00" * 47)))))
    pk = [(ts, len(d), d) for ts, _, d in pk]
    write_pcap(path, pk, link_type=113)


def write_pcapng(path):
    def block(btype, body):
        body += b"\x00" * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    out = shb + idb
    frames = [
        eth(MAC_GW, MAC_A, 0x0800, ipv4("10.2.2.2", "10.2.2.3", 6, tcp(41000, 443, 0x02))),
        eth(MAC_GW, MAC_A, 0x0800, ipv4("10.2.2.3", "10.2.2.2", 6, tcp(443, 41000, 0x12))),
        eth(MAC_GW, MAC_A, 0x0800, ipv4("10.2.2.2", "10.2.2.1", 17, udp(5353, 5353, b"mdns"))),
    ]
    for i, f in enumerate(frames):
        ts = int((T0 + i) * 1_000_000)
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(f), len(f)) + f
        out += block(6, body)
    with open(path, "wb") as fh:
        fh.write(out)


def main():
    os.makedirs(OUT, exist_ok=True)
    p = lambda n: os.path.join(OUT, n)

    normal = normal_packets()
    write_pcap(p("normal_traffic.pcap"), normal)

    mal = malformed_packets()
    write_pcap(p("malformed_packets.pcap"), mal)
    # packet 11: patch the microsecond field to an illegal value (>= 1,000,000)
    with open(p("malformed_packets.pcap"), "r+b") as fh:
        raw = fh.read()
        off = 24
        for i in range(1, 11):          # skip records 1-10, land on record 11
            caplen = struct.unpack_from("<I", raw, off + 8)[0]
            off += 16 + caplen
        fh.seek(off + 4)                    # ts_usec of packet 11's record header
        fh.write(struct.pack("<I", 4_000_000_000))

    # Truncated file: cut normal_traffic mid-way through packet 9's body
    with open(p("normal_traffic.pcap"), "rb") as fh:
        raw = fh.read()
    off = 24
    for _ in range(8):
        off += 16 + struct.unpack_from("<I", raw, off + 8)[0]
    with open(p("truncated_file.pcap"), "wb") as fh:
        fh.write(raw[:off + 16 + 20])       # full header of pkt 9, only 20 body bytes

    # Corrupt global header (bad magic)
    with open(p("corrupt_header.pcap"), "wb") as fh:
        fh.write(b"NOTAPCAP" + b"\x00" * 40)

    write_raw_ip(p("raw_ip.pcap"))
    write_sll(p("linux_cooked.pcap"))
    write_pcapng(p("sample.pcapng"))

    for name in sorted(os.listdir(OUT)):
        print(f"{name:<26}{os.path.getsize(p(name)):>7} bytes")


if __name__ == "__main__":
    main()
