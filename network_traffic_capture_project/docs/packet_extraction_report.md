# Packet-Extraction Report

Generated 2026-10-28 18:01 by `generate_report.py` from the files in `samples/`.

## 1. Test environment

| Item | Value |
|---|---|
| Tool | `packet_capture.py` (pure Python standard library, no third-party packages) |
| Python | 3.13.18 |
| Offline input | Classic PCAP (LE/BE, microsecond + nanosecond) and PCAPNG (SHB/IDB/EPB/SPB) |
| Link layers | Ethernet (+802.1Q/QinQ VLAN), Linux cooked (SLL), BSD loopback, raw IP |
| Network/transport | IPv4, IPv6 (with extension headers), ARP, TCP, UDP, SCTP ports, ICMP/ICMPv6 |
| Live capture | Linux `AF_PACKET` raw socket; needs root/`CAP_NET_RAW`, the `--authorized` flag, and optionally an interface allow-list |
| Sample data | Synthetic (RFC 1918 / documentation addresses) built by `make_samples.py`, plus one live loopback capture |

## 2. Fields extracted per packet

| Field | Source | When it is empty |
|---|---|---|
| timestamp / timestamp_iso | PCAP record header (UTC) | Timestamp fraction out of range, or PCAPNG simple packet block |
| src_ip / dst_ip | IPv4/IPv6 header; sender/target IP for ARP | Non-IP frame or IP header truncated |
| src_port / dst_port | TCP / UDP / SCTP header | ICMP/ARP/other protocols (normal), non-first fragment, header truncated |
| protocol | IP protocol number or EtherType name | Frame too short to read any header |
| captured_len / original_len | Record header | Never (always present once a record header is read) |
| ttl, tcp_flags, ip_total_len, src_mac, dst_mac, ip_version | IP/TCP/Ethernet headers | Same conditions as above |
| parse_status, errors | Parser | `ok` packets have no errors |

## 3. Results per sample file

| File | Format | Packets | ok | partial | malformed | File-level issues | Bytes captured |
|---|---|---|---|---|---|---|---|
| `corrupt_header.pcap` | unknown | 0 | 0 | 0 | 0 | 1 | 0 |
| `linux_cooked.pcap` | pcap | 3 | 3 | 0 | 0 | 0 | 204 |
| `live_loopback.pcap` | pcap | 12 | 12 | 0 | 0 | 0 | 576 |
| `malformed_packets.pcap` | pcap | 16 | 3 | 7 | 6 | 0 | 653 |
| `normal_traffic.pcap` | pcap | 16 | 16 | 0 | 0 | 0 | 1183 |
| `raw_ip.pcap` | pcap | 4 | 4 | 0 | 0 | 0 | 151 |
| `sample.pcapng` | pcapng | 3 | 3 | 0 | 0 | 0 | 154 |
| `truncated_file.pcap` | pcap | 9 | 8 | 0 | 1 | 1 | 749 |

**What each file is:**

- `corrupt_header.pcap`: Not a capture file: bad magic number
- `linux_cooked.pcap`: Link type 113 (Linux 'any' interface cooked capture)
- `live_loopback.pcap`: Real capture from the sandbox loopback interface (own test environment) via `capture --authorized`
- `malformed_packets.pcap`: 16 packets, 13 of them deliberately broken (empty, truncated headers, bad IHL, fragments, bad timestamp, ...)
- `normal_traffic.pcap`: Clean mixed traffic: ARP, DNS, TCP handshake + HTTP, ICMP, HTTPS SYN, VLAN-tagged SSH, IPv6 UDP/ICMPv6, syslog
- `raw_ip.pcap`: Link type 101 (raw IP, no Ethernet header)
- `sample.pcapng`: PCAPNG container with 3 Enhanced Packet Blocks
- `truncated_file.pcap`: normal_traffic.pcap cut off in the middle of packet 9

### 3.1 `normal_traffic.pcap` in detail

| # | Time (UTC) | Source | Destination | Proto | Bytes | Flags |
|---|---|---|---|---|---|---|
| 1 | 21:20:00.000000 | 192.168.1.10 | 192.168.1.1 | ARP | 42 |  |
| 2 | 21:20:00.010000 | 192.168.1.10:53211 | 192.168.1.1:53 | UDP | 71 |  |
| 3 | 21:20:00.020000 | 192.168.1.1:53 | 192.168.1.10:53211 | UDP | 90 |  |
| 4 | 21:20:00.030000 | 192.168.1.10:40000 | 93.184.216.34:80 | TCP | 54 | SYN |
| 5 | 21:20:00.040000 | 93.184.216.34:80 | 192.168.1.10:40000 | TCP | 54 | ACK,SYN |
| 6 | 21:20:00.050000 | 192.168.1.10:40000 | 93.184.216.34:80 | TCP | 54 | ACK |
| 7 | 21:20:00.060000 | 192.168.1.10:40000 | 93.184.216.34:80 | TCP | 91 | ACK,PSH |
| 8 | 21:20:00.070000 | 93.184.216.34:80 | 192.168.1.10:40000 | TCP | 273 | ACK,PSH |
| 9 | 21:20:00.080000 | 192.168.1.10 | 8.8.8.8 | ICMP | 50 |  |
| 10 | 21:20:00.090000 | 8.8.8.8 | 192.168.1.10 | ICMP | 50 |  |
| 11 | 21:20:00.100000 | 192.168.1.10:40001 | 151.101.1.69:443 | TCP | 54 | SYN |
| 12 | 21:20:00.110000 | 10.0.0.5:51000 | 10.0.0.9:22 | TCP | 58 | ACK |
| 13 | 21:20:00.120000 | 2001:db8::1:5000 | 2001:db8::2:5001 | UDP | 68 |  |
| 14 | 21:20:00.130000 | fe80::1 | ff02::1 | ICMPv6 | 62 |  |
| 15 | 21:20:00.140000 | 192.168.1.10:40000 | 93.184.216.34:80 | TCP | 54 | ACK,FIN |
| 16 | 21:20:00.150000 | 10.0.0.5:40514 | 10.0.0.9:514 | UDP | 58 |  |

Protocol mix: {'ARP': 1, 'UDP': 4, 'TCP': 8, 'ICMP': 2, 'ICMPv6': 1}. Total 1183 bytes, packet size min/avg/max = 42/73.9/273. The 4 packets without ports are the ARP, ICMP and ICMPv6 packets, which have no ports by design.

### 3.2 `malformed_packets.pcap`: how each bad packet was handled

| # | Status | Recovered | Problem(s) recorded |
|---|---|---|---|
| 1 | ok | src=192.168.1.10, ports=40000->80, proto=TCP | - |
| 2 | malformed | nothing | empty packet (0 bytes captured) |
| 3 | malformed | nothing | truncated Ethernet header (5/14 bytes) |
| 4 | malformed | proto=IPv4 | truncated IPv4 header (6/20 bytes) |
| 5 | malformed | src=192.168.1.10, ports=1234->80, proto=TCP | invalid IPv4 header length 12 (<20) |
| 6 | partial | src=192.168.1.10, ports=5555->443, proto=TCP | IPv4 total length 1500 exceeds captured bytes 60 (truncated capture) |
| 7 | partial | src=192.168.1.10, proto=TCP | IPv4 total length 40 exceeds captured bytes 22 (truncated capture); truncated TCP header; ports unavailable |
| 8 | partial | src=192.168.1.10, ports=6000->8080, proto=TCP | IPv4 total length 40 exceeds captured bytes 26 (truncated capture); truncated TCP header; flags unavailable |
| 9 | partial | proto=ETH-0x88cc | non-IP EtherType 0x88cc; no IP/port fields |
| 10 | partial | src=192.168.1.10, proto=UDP | non-first IPv4 fragment (offset 1480); ports unavailable |
| 11 | partial | src=192.168.1.10, ports=40002->22, proto=TCP | timestamp fraction 4000000000 out of range |
| 12 | malformed | proto=IPv6 | truncated IPv6 header (25/40 bytes) |
| 13 | ok | src=192.168.1.10, proto=IP-PROTO-253 | - |
| 14 | partial | src=192.168.1.10, ports=40003->25, proto=TCP | captured length 54 > original length 20 |
| 15 | malformed | proto=ARP | truncated ARP packet |
| 16 | ok | src=192.168.1.10, ports=40004->8443, proto=TCP | - |

Missing-field counts for this file: {'timestamp': 1, 'src_ip': 6, 'dst_ip': 6, 'src_port': 9, 'dst_port': 9, 'protocol': 2}. Every packet still produced a row, and packet 16 (valid) was parsed correctly after the bad ones.

**File-level issues in `corrupt_header.pcap`:** bad PCAP magic number 4e4f5441

**File-level issues in `truncated_file.pcap`:** packet 9: body cut off by end of file

## 4. Malformed-packet and missing-field policy

| Situation | Behaviour |
|---|---|
| Truncated or short header | Fields read before the cut are kept; the rest are empty; status `partial` or `malformed` |
| Invalid IPv4 header length (IHL < 5) | Flagged `malformed`; addresses still read from the fixed 20-byte layout |
| IP length larger than captured bytes | Flagged as truncated capture (`partial`); not treated as corruption |
| Non-first IP fragment | IPs kept, ports left empty, `partial` |
| Unknown EtherType / IP protocol | Protocol shown as `ETH-0x....` / `IP-PROTO-n`; no crash |
| Timestamp fraction out of range | Timestamp left empty, rest of packet parsed |
| Captured length > original length | Flagged `partial` |
| File ends mid-record | Partial record kept (malformed), reading stops, issue logged at file level |
| Bad magic / empty file / missing file | Zero packets, issue logged, exit code 0 and no traceback |
| Implausible record length (> ~1 MiB) | Reading stops (stream is out of sync), issue logged |
| Anything unexpected inside the parser | Caught per packet, recorded as `malformed`, next packet continues |

`ok` = fully parsed; `partial` = IP-level fields usable but something is missing or inconsistent; `malformed` = a header could not be read or is invalid.

## 5. Live capture check

A real capture on the sandbox loopback interface (`lo`, my own test environment) with `--authorized --allow-interfaces lo` while 6 UDP datagrams were sent to 127.0.0.1:9191 recorded 12 packets, all `ok`, protocol {'UDP': 12}. Each datagram appears twice because an `AF_PACKET` socket on `lo` sees both the outgoing and the incoming copy; that is normal Linux behaviour, not a parser fault. The saved PCAP re-reads to the same packet count.

Without `--authorized`, or with an interface not on the allow-list, the tool refuses and exits with code 2.

## 6. Verification

`python3 -m unittest test_packet_capture`: **Ran 32 tests in 0.025s, OK**. The tests check exact field values (IPs, ports, flags, sizes, timestamps) for the clean sample, the exact ok/partial/malformed split (3/7/6) and per-packet outcomes for the malformed sample, file-level failures, big-endian and nanosecond PCAP, PCAPNG, raw-IP and Linux-cooked inputs, CSV/JSON round-trip, the live-capture authorization guard, and 300 random byte blobs fed through every link type to confirm the parser never raises.

## 7. Known limitations

- No TCP stream reassembly or IP defragmentation; only the first fragment yields ports.
- Tunnels (GRE, IP-in-IP, VXLAN) are reported by outer headers only.
- PCAPNG: only SHB, IDB, EPB and SPB blocks are read; other block types are skipped.
- Live capture is Linux-only. On other platforms capture with tcpdump/Wireshark and use `read`.
- IPv4 header checksums are not validated.
