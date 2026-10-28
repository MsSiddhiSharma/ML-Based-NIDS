#!/usr/bin/env python3
"""
packet_capture.py - Network traffic capture and packet-field extraction.

Reads classic PCAP files (and basic PCAPNG) or captures from an *authorized*
test interface, and extracts per-packet:

    timestamp, source/destination IP, source/destination port, protocol,
    packet size (captured + original length)

Malformed or truncated packets never crash the run: every packet gets a
record, missing fields are None (empty in CSV), and a `parse_status` /
`errors` pair says what went wrong. Pure standard library, no root needed
for offline PCAP reading.

Usage
-----
  # Offline: read one or more PCAP files
  python3 packet_capture.py read samples/normal_traffic.pcap \
        --csv output/normal.csv --json output/normal.json

  # Live (Linux only, needs root/CAP_NET_RAW, explicit authorization flag)
  sudo python3 packet_capture.py capture --interface lo --count 100 \
        --authorized --pcap-out output/live.pcap --csv output/live.csv

  # Human-readable summary of what was extracted
  python3 packet_capture.py read samples/*.pcap --summary
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),   # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),   # big-endian,    microsecond
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian,    nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

LINKTYPE_NULL = 0          # BSD loopback
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101         # raw IPv4/IPv6
LINKTYPE_LINUX_SLL = 113   # Linux cooked capture
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_IPV6 = 0x86DD

IP_PROTOS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IPv4",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}
IPV6_EXT_HEADERS = {0, 43, 44, 60}     # hop-by-hop, routing, fragment, dest-opts

MAX_SANE_CAPLEN = 262_144 * 4          # refuse absurd record sizes (~1 MiB)

CSV_FIELDS = [
    "packet_no", "timestamp", "timestamp_iso", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "ip_version", "captured_len",
    "original_len", "ip_total_len", "ttl", "tcp_flags", "src_mac", "dst_mac",
    "parse_status", "errors",
]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class PacketRecord:
    packet_no: int
    timestamp: Optional[float] = None        # epoch seconds
    timestamp_iso: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    ip_version: Optional[int] = None
    captured_len: Optional[int] = None       # bytes actually stored
    original_len: Optional[int] = None       # bytes on the wire
    ip_total_len: Optional[int] = None
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    parse_status: str = "ok"                 # ok | partial | malformed
    errors: List[str] = field(default_factory=list)

    def err(self, msg: str, severity: str = "partial") -> None:
        """Record a problem; never downgrade 'malformed' back to 'partial'."""
        self.errors.append(msg)
        if self.parse_status != "malformed":
            self.parse_status = severity

    def as_row(self) -> Dict[str, object]:
        d = asdict(self)
        d["errors"] = "; ".join(self.errors)
        return d


@dataclass
class ReadStats:
    source: str
    format: str = "unknown"
    link_type: Optional[int] = None
    file_issues: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #

def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat(
            timespec="microseconds")
    except (OverflowError, OSError, ValueError):
        return None


def _tcp_flag_string(flags: int) -> str:
    names = [(0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"), (0x10, "ACK"),
             (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")]
    return ",".join(n for bit, n in names if flags & bit) or "NONE"


# --------------------------------------------------------------------------- #
# Packet dissection
# --------------------------------------------------------------------------- #

def parse_packet(data: bytes, link_type: int, rec: PacketRecord) -> PacketRecord:
    """Fill `rec` from raw packet bytes. Never raises on bad input."""
    try:
        _parse_link(data, link_type, rec)
    except Exception as exc:   # last-resort guard: record, don't crash
        rec.err(f"unexpected parser error: {type(exc).__name__}: {exc}",
                "malformed")
    return rec


def _parse_link(data: bytes, link_type: int, rec: PacketRecord) -> None:
    if len(data) == 0:
        rec.err("empty packet (0 bytes captured)", "malformed")
        return

    if link_type == LINKTYPE_ETHERNET:
        if len(data) < 14:
            rec.err(f"truncated Ethernet header ({len(data)}/14 bytes)",
                    "malformed")
            return
        rec.dst_mac, rec.src_mac = _mac(data[0:6]), _mac(data[6:12])
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        vlan_depth = 0
        while ethertype in (ETH_VLAN, ETH_QINQ) and vlan_depth < 4:
            if len(data) < offset + 4:
                rec.err("truncated VLAN tag", "malformed")
                return
            ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
            vlan_depth += 1
        _parse_ethertype(data, offset, ethertype, rec)

    elif link_type == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            rec.err(f"truncated Linux cooked header ({len(data)}/16 bytes)",
                    "malformed")
            return
        ethertype = struct.unpack("!H", data[14:16])[0]
        _parse_ethertype(data, 16, ethertype, rec)

    elif link_type == LINKTYPE_NULL:
        if len(data) < 4:
            rec.err("truncated loopback header", "malformed")
            return
        fam_le = struct.unpack("<I", data[:4])[0]
        fam_be = struct.unpack(">I", data[:4])[0]
        fam = fam_le if fam_le < 256 else fam_be
        if fam == socket.AF_INET:
            _parse_ipv4(data, 4, rec)
        elif fam in (socket.AF_INET6, 24, 28, 30):   # Linux/BSD/macOS values
            _parse_ipv6(data, 4, rec)
        else:
            rec.protocol = f"AF-{fam}"
            rec.err(f"unsupported loopback address family {fam}")

    elif link_type in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        version = data[0] >> 4
        if version == 4:
            _parse_ipv4(data, 0, rec)
        elif version == 6:
            _parse_ipv6(data, 0, rec)
        else:
            rec.err(f"raw packet has unknown IP version nibble {version}",
                    "malformed")
    else:
        rec.err(f"unsupported link type {link_type}")


def _parse_ethertype(data: bytes, off: int, ethertype: int,
                     rec: PacketRecord) -> None:
    if ethertype == ETH_IPV4:
        _parse_ipv4(data, off, rec)
    elif ethertype == ETH_IPV6:
        _parse_ipv6(data, off, rec)
    elif ethertype == ETH_ARP:
        _parse_arp(data, off, rec)
    else:
        rec.protocol = f"ETH-0x{ethertype:04x}"
        rec.err(f"non-IP EtherType 0x{ethertype:04x}; no IP/port fields")


def _parse_arp(data: bytes, off: int, rec: PacketRecord) -> None:
    rec.protocol = "ARP"
    if len(data) < off + 28:
        rec.err("truncated ARP packet", "malformed")
        return
    # Ethernet/IPv4 ARP: sender IP at +14, target IP at +24
    htype, ptype, hlen, plen = struct.unpack("!HHBB", data[off:off + 6])
    if ptype == ETH_IPV4 and plen == 4:
        rec.src_ip = socket.inet_ntoa(data[off + 14:off + 18])
        rec.dst_ip = socket.inet_ntoa(data[off + 24:off + 28])
        rec.ip_version = 4
    else:
        rec.err("ARP with non-IPv4 protocol type; IPs not extracted")


def _parse_ipv4(data: bytes, off: int, rec: PacketRecord) -> None:
    if len(data) < off + 20:
        rec.protocol = "IPv4"
        rec.err(f"truncated IPv4 header ({len(data) - off}/20 bytes)",
                "malformed")
        return
    vihl = data[off]
    version, ihl = vihl >> 4, (vihl & 0x0F) * 4
    if version != 4:
        rec.err(f"IPv4 header has version nibble {version}", "malformed")
        return
    rec.ip_version = 4
    if ihl < 20:
        rec.err(f"invalid IPv4 header length {ihl} (<20)", "malformed")
        ihl = 20     # still extract addresses; header layout is fixed
    total_len = struct.unpack("!H", data[off + 2:off + 4])[0]
    frag = struct.unpack("!H", data[off + 6:off + 8])[0]
    rec.ttl = data[off + 8]
    proto = data[off + 9]
    rec.src_ip = socket.inet_ntoa(data[off + 12:off + 16])
    rec.dst_ip = socket.inet_ntoa(data[off + 16:off + 20])
    rec.ip_total_len = total_len
    rec.protocol = IP_PROTOS.get(proto, f"IP-PROTO-{proto}")

    avail = len(data) - off
    if total_len < ihl:
        rec.err(f"IPv4 total length {total_len} smaller than header {ihl}")
    elif total_len > avail:
        rec.err(f"IPv4 total length {total_len} exceeds captured bytes {avail}"
                " (truncated capture)")
    if len(data) < off + ihl:
        rec.err("IPv4 options extend past captured data")
        return

    frag_offset = frag & 0x1FFF
    if frag_offset != 0:
        rec.err(f"non-first IPv4 fragment (offset {frag_offset * 8}); "
                "ports unavailable")
        return
    _parse_transport(data, off + ihl, proto, rec)


def _parse_ipv6(data: bytes, off: int, rec: PacketRecord) -> None:
    if len(data) < off + 40:
        rec.protocol = "IPv6"
        rec.err(f"truncated IPv6 header ({len(data) - off}/40 bytes)",
                "malformed")
        return
    if data[off] >> 4 != 6:
        rec.err(f"IPv6 header has version nibble {data[off] >> 4}",
                "malformed")
        return
    rec.ip_version = 6
    payload_len = struct.unpack("!H", data[off + 4:off + 6])[0]
    nxt = data[off + 6]
    rec.ttl = data[off + 7]                      # hop limit
    rec.src_ip = str(ipaddress.IPv6Address(data[off + 8:off + 24]))
    rec.dst_ip = str(ipaddress.IPv6Address(data[off + 24:off + 40]))
    rec.ip_total_len = payload_len + 40
    cur = off + 40
    # walk extension headers
    hops = 0
    while nxt in IPV6_EXT_HEADERS and hops < 8:
        if nxt == 44:    # fragment header: fixed 8 bytes
            if len(data) < cur + 8:
                rec.protocol = "IPv6"
                rec.err("truncated IPv6 fragment header")
                return
            frag_off = struct.unpack("!H", data[cur + 2:cur + 4])[0] >> 3
            nxt_new = data[cur]
            cur += 8
            if frag_off != 0:
                rec.protocol = IP_PROTOS.get(nxt_new, f"IP-PROTO-{nxt_new}")
                rec.err("non-first IPv6 fragment; ports unavailable")
                return
            nxt = nxt_new
        else:
            if len(data) < cur + 2:
                rec.protocol = "IPv6"
                rec.err("truncated IPv6 extension header")
                return
            nxt_new, hdr_len = data[cur], (data[cur + 1] + 1) * 8
            cur += hdr_len
            nxt = nxt_new
        hops += 1
    rec.protocol = IP_PROTOS.get(nxt, f"IP-PROTO-{nxt}")
    if payload_len + 40 > len(data) - off:
        rec.err("IPv6 payload length exceeds captured bytes "
                "(truncated capture)")
    _parse_transport(data, cur, nxt, rec)


def _parse_transport(data: bytes, off: int, proto: int,
                     rec: PacketRecord) -> None:
    if proto == 6:        # TCP
        if len(data) < off + 4:
            rec.err("truncated TCP header; ports unavailable")
            return
        rec.src_port, rec.dst_port = struct.unpack("!HH", data[off:off + 4])
        if len(data) >= off + 14:
            rec.tcp_flags = _tcp_flag_string(data[off + 13])
        else:
            rec.err("truncated TCP header; flags unavailable")
    elif proto == 17:     # UDP
        if len(data) < off + 4:
            rec.err("truncated UDP header; ports unavailable")
            return
        rec.src_port, rec.dst_port = struct.unpack("!HH", data[off:off + 4])
    elif proto == 132:    # SCTP
        if len(data) < off + 4:
            rec.err("truncated SCTP header; ports unavailable")
            return
        rec.src_port, rec.dst_port = struct.unpack("!HH", data[off:off + 4])
    # ICMP and other protocols legitimately have no ports: not an error.


# --------------------------------------------------------------------------- #
# File readers
# --------------------------------------------------------------------------- #

def _read_exact(fh, n: int) -> bytes:
    return fh.read(n)


def iter_pcap_packets(path: str, stats: ReadStats
                      ) -> Iterator[Tuple[int, Optional[float], int, int, bytes, List[str]]]:
    """Yield (index, ts, caplen, origlen, data, notes) for each record."""
    with open(path, "rb") as fh:
        header = _read_exact(fh, 24)
        if len(header) < 24:
            stats.file_issues.append(
                f"file too short for a PCAP global header ({len(header)}/24 bytes)")
            return
        magic = header[:4]
        if magic not in PCAP_MAGICS:
            stats.file_issues.append(f"bad PCAP magic number {magic.hex()}")
            return
        endian, res = PCAP_MAGICS[magic]
        stats.format = "pcap" + ("-nsec" if res == 1_000_000_000 else "")
        _, vmaj, vmin, _, _, snaplen, linktype = struct.unpack(
            endian + "4sHHiIII", header)
        stats.link_type = linktype
        idx = 0
        while True:
            rh = _read_exact(fh, 16)
            if len(rh) == 0:
                return                                    # clean EOF
            if len(rh) < 16:
                stats.file_issues.append(
                    f"truncated record header after packet {idx} "
                    f"({len(rh)}/16 bytes); stopping")
                return
            ts_sec, ts_frac, caplen, origlen = struct.unpack(endian + "IIII", rh)
            notes: List[str] = []
            idx += 1
            if caplen > MAX_SANE_CAPLEN or (snaplen and caplen > max(snaplen, 65535) * 4):
                stats.file_issues.append(
                    f"packet {idx}: implausible captured length {caplen}; "
                    "record stream is corrupt, stopping")
                return
            data = _read_exact(fh, caplen)
            if len(data) < caplen:
                notes.append(f"packet body truncated by end of file "
                             f"({len(data)}/{caplen} bytes)")
                stats.file_issues.append(
                    f"packet {idx}: body cut off by end of file")
            if ts_frac >= res:
                notes.append(f"timestamp fraction {ts_frac} out of range")
                ts = None
            else:
                ts = ts_sec + ts_frac / res
            if caplen > origlen:
                notes.append(f"captured length {caplen} > original length {origlen}")
            yield idx, ts, len(data), origlen, data, notes
            if len(data) < caplen:
                return


def iter_pcapng_packets(path: str, stats: ReadStats):
    """Minimal PCAPNG reader: SHB, IDB, EPB, SPB, legacy PB."""
    stats.format = "pcapng"
    with open(path, "rb") as fh:
        raw = fh.read()
    pos, endian = 0, "<"
    ifaces: List[Tuple[int, int]] = []      # (linktype, ts_divisor)
    idx = 0
    while pos + 12 <= len(raw):
        if raw[pos:pos + 4] == PCAPNG_MAGIC:
            bom = raw[pos + 8:pos + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                stats.file_issues.append("pcapng: bad byte-order magic")
                return
            ifaces = []
        btype, blen = struct.unpack(endian + "II", raw[pos:pos + 8])
        if blen < 12 or blen % 4 or pos + blen > len(raw):
            stats.file_issues.append(
                f"pcapng: bad/truncated block (type {btype:#x}, len {blen}) "
                f"at offset {pos}; stopping")
            return
        body = raw[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 8:                      # IDB
            lt = struct.unpack(endian + "H", body[:2])[0]
            div = 1_000_000
            opts = body[8:]
            while len(opts) >= 4:
                code, olen = struct.unpack(endian + "HH", opts[:4])
                if code == 0:
                    break
                val = opts[4:4 + olen]
                if code == 9 and olen >= 1:                    # if_tsresol
                    r = val[0]
                    div = 2 ** (r & 0x7F) if r & 0x80 else 10 ** r
                opts = opts[4 + ((olen + 3) & ~3):]
            ifaces.append((lt, div))
            if stats.link_type is None:
                stats.link_type = lt
        elif btype == 6 and len(body) >= 20:                   # EPB
            iid, hi, lo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            notes: List[str] = []
            data = body[20:20 + cap]
            if len(data) < cap:
                notes.append("pcapng packet data shorter than caplen")
            lt, div = ifaces[iid] if iid < len(ifaces) else (1, 1_000_000)
            if iid >= len(ifaces):
                notes.append(f"unknown interface id {iid}; assuming Ethernet")
            idx += 1
            yield idx, ((hi << 32) | lo) / div, len(data), orig, data, notes, lt
        elif btype == 3 and len(body) >= 4:                    # SPB
            orig = struct.unpack(endian + "I", body[:4])[0]
            data = body[4:4 + orig]
            lt = ifaces[0][0] if ifaces else 1
            idx += 1
            yield (idx, None, len(data), orig, data,
                   ["simple packet block has no timestamp"], lt)
        pos += blen


def read_packets(path: str) -> Tuple[List[PacketRecord], ReadStats]:
    """Read a capture file and return (records, stats). Never raises on bad data."""
    stats = ReadStats(source=os.path.basename(path))
    records: List[PacketRecord] = []
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        stats.file_issues.append(f"cannot open file: {exc}")
        return records, stats
    if len(magic) < 4:
        stats.file_issues.append("file is empty or shorter than 4 bytes")
        return records, stats

    if magic == PCAPNG_MAGIC:
        gen = iter_pcapng_packets(path, stats)
        for item in gen:
            idx, ts, caplen, origlen, data, notes, lt = item
            rec = PacketRecord(packet_no=idx, timestamp=ts,
                               timestamp_iso=_iso(ts), captured_len=caplen,
                               original_len=origlen)
            for n in notes:
                rec.err(n)
            parse_packet(data, lt, rec)
            if caplen < origlen:
                pass    # snaplen-truncated: normal, not an error
            records.append(rec)
    else:
        for idx, ts, caplen, origlen, data, notes in iter_pcap_packets(path, stats):
            rec = PacketRecord(packet_no=idx, timestamp=ts,
                               timestamp_iso=_iso(ts), captured_len=caplen,
                               original_len=origlen)
            for n in notes:
                rec.err(n)
            parse_packet(data, stats.link_type if stats.link_type is not None
                         else LINKTYPE_ETHERNET, rec)
            records.append(rec)
    return records, stats


# --------------------------------------------------------------------------- #
# Live capture (authorized interfaces only)
# --------------------------------------------------------------------------- #

class AuthorizationError(RuntimeError):
    pass


def _check_authorization(interface: str, authorized: bool,
                         allow_list: Optional[List[str]]) -> None:
    if not authorized:
        raise AuthorizationError(
            "Live capture refused: pass --authorized to confirm you have "
            "permission to capture on this interface/network.")
    if allow_list is not None and interface not in allow_list:
        raise AuthorizationError(
            f"Interface '{interface}' is not in the allowed list "
            f"{allow_list}.")


def live_capture(interface: str, count: int = 100, timeout: float = 30.0,
                 snaplen: int = 65535, authorized: bool = False,
                 allow_list: Optional[List[str]] = None,
                 pcap_out: Optional[str] = None
                 ) -> Tuple[List[PacketRecord], ReadStats]:
    """Capture up to `count` packets (or until `timeout` s) from `interface`.

    Linux AF_PACKET only; requires root or CAP_NET_RAW.
    """
    _check_authorization(interface, authorized, allow_list)
    if not hasattr(socket, "AF_PACKET"):
        raise OSError("Live capture needs Linux AF_PACKET sockets "
                      "(not available on this platform). Use `read` on a PCAP.")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(0x0003))        # ETH_P_ALL
        sock.bind((interface, 0))
    except PermissionError:
        raise PermissionError(
            "Raw capture needs root or CAP_NET_RAW "
            "(try: sudo python3 packet_capture.py capture ...)")
    except OSError as exc:
        raise OSError(f"Cannot open interface '{interface}': {exc}")

    stats = ReadStats(source=f"live:{interface}", format="live",
                      link_type=LINKTYPE_ETHERNET)
    records: List[PacketRecord] = []
    raw_packets: List[Tuple[float, int, bytes]] = []
    deadline = time.time() + timeout
    sock.settimeout(1.0)
    try:
        while len(records) < count and time.time() < deadline:
            try:
                data, _addr = sock.recvfrom(snaplen + 4)
            except socket.timeout:
                continue
            ts = time.time()
            orig = len(data)
            data = data[:snaplen]
            raw_packets.append((ts, orig, data))
            rec = PacketRecord(packet_no=len(records) + 1, timestamp=ts,
                               timestamp_iso=_iso(ts), captured_len=len(data),
                               original_len=orig)
            parse_packet(data, LINKTYPE_ETHERNET, rec)
            records.append(rec)
    except KeyboardInterrupt:
        stats.file_issues.append("capture interrupted by user")
    finally:
        sock.close()
    if pcap_out:
        write_pcap(pcap_out, raw_packets, LINKTYPE_ETHERNET, snaplen)
    return records, stats


def write_pcap(path: str, packets: Iterable[Tuple[float, int, bytes]],
               link_type: int = LINKTYPE_ETHERNET, snaplen: int = 65535) -> int:
    """Write (timestamp, original_len, data) tuples as a little-endian PCAP."""
    n = 0
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen,
                             link_type))
        for ts, orig, data in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(data), orig))
            fh.write(data)
            n += 1
    return n


# --------------------------------------------------------------------------- #
# Output + reporting
# --------------------------------------------------------------------------- #

def write_csv(path: str, records: List[PacketRecord]) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in records:
            row = r.as_row()
            w.writerow({k: ("" if row[k] is None else row[k]) for k in CSV_FIELDS})


def write_json(path: str, records: List[PacketRecord], stats: ReadStats) -> None:
    payload = {"source": stats.source, "format": stats.format,
               "link_type": stats.link_type, "file_issues": stats.file_issues,
               "packet_count": len(records),
               "packets": [r.as_row() for r in records]}
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)


def summarize(records: List[PacketRecord], stats: ReadStats) -> Dict[str, object]:
    """Aggregate numbers used by --summary and the report generator."""
    n = len(records)
    status = Counter(r.parse_status for r in records)
    field_names = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                   "protocol", "captured_len"]
    missing = {f: sum(1 for r in records if getattr(r, f) is None)
               for f in field_names}
    sizes = [r.captured_len for r in records if r.captured_len is not None]
    stamps = [r.timestamp for r in records if r.timestamp is not None]
    issue_counter: Counter = Counter()
    for r in records:
        for e in r.errors:
            # normalise numbers so identical problems group together
            key = "".join("#" if c.isdigit() else c for c in e)
            issue_counter[key] += 1
    return {
        "source": stats.source, "format": stats.format,
        "link_type": stats.link_type, "packets": n,
        "status": dict(status), "missing_fields": missing,
        "protocols": dict(Counter(r.protocol or "unknown" for r in records)),
        "top_talkers": Counter(r.src_ip for r in records if r.src_ip
                               ).most_common(5),
        "top_dst_ports": Counter(r.dst_port for r in records
                                 if r.dst_port is not None).most_common(5),
        "bytes_total": sum(sizes),
        "size_min": min(sizes) if sizes else None,
        "size_max": max(sizes) if sizes else None,
        "size_avg": round(sum(sizes) / len(sizes), 1) if sizes else None,
        "time_first": min(stamps) if stamps else None,
        "time_last": max(stamps) if stamps else None,
        "issues": dict(issue_counter.most_common()),
        "file_issues": stats.file_issues,
    }


def print_summary(s: Dict[str, object], out=sys.stdout) -> None:
    p = lambda *a: print(*a, file=out)
    p(f"== {s['source']}  [{s['format']}, linktype={s['link_type']}] ==")
    p(f"packets: {s['packets']}   bytes captured: {s['bytes_total']}   "
      f"size min/avg/max: {s['size_min']}/{s['size_avg']}/{s['size_max']}")
    p(f"parse status: {s['status']}")
    p(f"protocols: {s['protocols']}")
    p(f"missing fields: { {k: v for k, v in s['missing_fields'].items() if v} or 'none'}")
    if s["top_talkers"]:
        p(f"top sources: {s['top_talkers']}")
    if s["top_dst_ports"]:
        p(f"top dst ports: {s['top_dst_ports']}")
    if s["issues"]:
        p("packet issues:")
        for k, v in s["issues"].items():
            p(f"  {v:>4} x {k}")
    if s["file_issues"]:
        p("file-level issues:")
        for i in s["file_issues"]:
            p(f"  - {i}")
    p()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _emit(records: List[PacketRecord], stats: ReadStats,
          args: argparse.Namespace, multi: bool) -> None:
    def target(p: Optional[str]) -> Optional[str]:
        if not p or not multi:
            return p
        root, ext = os.path.splitext(p)
        stem = os.path.splitext(stats.source)[0]
        return f"{root}_{stem}{ext}"
    if args.csv:
        write_csv(target(args.csv), records)
    if args.json:
        write_json(target(args.json), records, stats)
    if args.summary or not (args.csv or args.json or args.quiet):
        print_summary(summarize(records, stats))
    if args.show:
        for r in records[:args.show]:
            print(f"#{r.packet_no:<4} {r.timestamp_iso or '-':<32} "
                  f"{r.src_ip or '-':>15}:{r.src_port if r.src_port is not None else '-':<5} -> "
                  f"{r.dst_ip or '-':>15}:{r.dst_port if r.dst_port is not None else '-':<5} "
                  f"{r.protocol or '-':<8} {r.captured_len}B "
                  f"[{r.parse_status}]")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Extract IPs, ports, protocol, size and timestamps from "
                    "PCAP files or an authorized test interface.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--csv", help="write per-packet CSV")
        p.add_argument("--json", help="write per-packet JSON")
        p.add_argument("--summary", action="store_true",
                       help="print aggregate summary")
        p.add_argument("--show", type=int, metavar="N", default=0,
                       help="print the first N packets as text")
        p.add_argument("--quiet", action="store_true",
                       help="no default summary when writing files")

    r = sub.add_parser("read", help="read PCAP/PCAPNG file(s)")
    r.add_argument("files", nargs="+")
    common(r)

    c = sub.add_parser("capture", help="live capture (Linux, root, authorized)")
    c.add_argument("--interface", "-i", required=True)
    c.add_argument("--count", "-c", type=int, default=100)
    c.add_argument("--timeout", type=float, default=30.0)
    c.add_argument("--snaplen", type=int, default=65535)
    c.add_argument("--authorized", action="store_true",
                   help="confirm you are authorized to capture on this interface")
    c.add_argument("--allow-interfaces", nargs="*", default=None,
                   help="optional allow-list of interface names")
    c.add_argument("--pcap-out", help="also save raw capture as PCAP")
    common(c)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "read":
        multi = len(args.files) > 1
        for path in args.files:
            records, stats = read_packets(path)
            _emit(records, stats, args, multi)
        return 0
    try:
        records, stats = live_capture(
            args.interface, args.count, args.timeout, args.snaplen,
            args.authorized, args.allow_interfaces, args.pcap_out)
    except (AuthorizationError, PermissionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(records, stats, args, multi=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
