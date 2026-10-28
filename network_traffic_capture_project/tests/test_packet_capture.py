#!/usr/bin/env python3
"""Unit tests for packet_capture.py. Run: python3 -m unittest -v test_packet_capture"""

import os
import sys
import struct
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
sys.path.insert(0, ROOT)
sys.path.insert(0, TOOLS)

import packet_capture as pc
import make_samples as ms

HERE = ROOT
S = lambda n: os.path.join(HERE, "samples", n)


class NormalTraffic(unittest.TestCase):
    def setUp(self):
        self.recs, self.stats = pc.read_packets(S("normal_traffic.pcap"))

    def test_counts_and_status(self):
        self.assertEqual(len(self.recs), 16)
        self.assertTrue(all(r.parse_status == "ok" for r in self.recs))
        self.assertEqual(self.stats.file_issues, [])

    def test_tcp_syn_fields(self):
        r = self.recs[3]                        # packet 4: TCP SYN
        self.assertEqual((r.src_ip, r.dst_ip), ("192.168.1.10", "93.184.216.34"))
        self.assertEqual((r.src_port, r.dst_port), (40000, 80))
        self.assertEqual(r.protocol, "TCP")
        self.assertEqual(r.tcp_flags, "SYN")
        self.assertEqual(r.captured_len, 54)
        self.assertEqual(r.original_len, 54)
        self.assertEqual(r.ttl, 64)

    def test_timestamps(self):
        self.assertAlmostEqual(self.recs[0].timestamp, ms.T0, places=6)
        self.assertAlmostEqual(self.recs[15].timestamp - self.recs[0].timestamp,
                               0.15, places=5)
        self.assertTrue(self.recs[0].timestamp_iso.endswith("+00:00"))

    def test_protocol_mix(self):
        s = pc.summarize(self.recs, self.stats)
        self.assertEqual(s["protocols"],
                         {"ARP": 1, "UDP": 4, "TCP": 8, "ICMP": 2, "ICMPv6": 1})

    def test_icmp_and_arp_have_no_ports_but_are_ok(self):
        for i in (0, 8, 9, 13):
            self.assertIsNone(self.recs[i].src_port)
            self.assertEqual(self.recs[i].parse_status, "ok")

    def test_vlan_tagged(self):
        r = self.recs[11]
        self.assertEqual((r.src_ip, r.dst_port, r.protocol), ("10.0.0.5", 22, "TCP"))
        self.assertEqual(r.captured_len, 58)

    def test_ipv6(self):
        r = self.recs[12]
        self.assertEqual((r.src_ip, r.dst_ip), ("2001:db8::1", "2001:db8::2"))
        self.assertEqual((r.src_port, r.dst_port, r.ip_version), (5000, 5001, 6))


class MalformedTraffic(unittest.TestCase):
    def setUp(self):
        self.recs, self.stats = pc.read_packets(S("malformed_packets.pcap"))
        self.by = {r.packet_no: r for r in self.recs}

    def test_every_packet_gets_a_record(self):
        self.assertEqual(len(self.recs), 16)

    def test_status_totals(self):
        s = pc.summarize(self.recs, self.stats)["status"]
        self.assertEqual(s, {"ok": 3, "partial": 7, "malformed": 6})

    def test_ok_packets(self):
        self.assertEqual(sorted(n for n, r in self.by.items()
                                if r.parse_status == "ok"), [1, 13, 16])

    def test_empty_and_short_frames(self):
        for n in (2, 3):
            self.assertEqual(self.by[n].parse_status, "malformed")
            self.assertIsNone(self.by[n].src_ip)
        self.assertEqual(self.by[2].captured_len, 0)

    def test_truncated_headers_keep_what_they_can(self):
        self.assertEqual(self.by[4].protocol, "IPv4")
        self.assertIsNone(self.by[4].src_ip)
        r7 = self.by[7]                         # ports cut off
        self.assertEqual(r7.src_ip, "192.168.1.10")
        self.assertIsNone(r7.src_port)
        r8 = self.by[8]                         # ports present, flags cut off
        self.assertEqual((r8.src_port, r8.dst_port), (6000, 8080))
        self.assertIsNone(r8.tcp_flags)

    def test_bad_ihl_flagged_but_addresses_recovered(self):
        r = self.by[5]
        self.assertEqual(r.parse_status, "malformed")
        self.assertEqual(r.dst_ip, "93.184.216.34")

    def test_snaplen_style_truncation(self):
        r = self.by[6]
        self.assertEqual(r.parse_status, "partial")
        self.assertEqual(r.original_len, 1514)
        self.assertEqual(r.ip_total_len, 1500)

    def test_non_ip_and_fragment_and_unknown_proto(self):
        self.assertEqual(self.by[9].protocol, "ETH-0x88cc")
        self.assertIsNone(self.by[10].src_port)
        self.assertEqual(self.by[10].parse_status, "partial")
        self.assertEqual(self.by[13].protocol, "IP-PROTO-253")

    def test_bad_timestamp_is_none_not_crash(self):
        r = self.by[11]
        self.assertIsNone(r.timestamp)
        self.assertIsNone(r.timestamp_iso)
        self.assertEqual(r.dst_port, 22)       # rest of the packet still parsed

    def test_parser_recovers_after_bad_packets(self):
        self.assertEqual(self.by[16].dst_port, 8443)


class FileLevelProblems(unittest.TestCase):
    def test_truncated_file(self):
        recs, st = pc.read_packets(S("truncated_file.pcap"))
        self.assertEqual(len(recs), 9)
        self.assertEqual(recs[8].parse_status, "malformed")
        self.assertTrue(any("cut off" in i for i in st.file_issues))

    def test_bad_magic(self):
        recs, st = pc.read_packets(S("corrupt_header.pcap"))
        self.assertEqual(recs, [])
        self.assertTrue(any("magic" in i for i in st.file_issues))

    def test_missing_and_empty_files(self):
        recs, st = pc.read_packets(S("does_not_exist.pcap"))
        self.assertEqual((recs, len(st.file_issues)), ([], 1))
        with tempfile.NamedTemporaryFile(suffix=".pcap") as tf:
            recs, st = pc.read_packets(tf.name)
            self.assertEqual(recs, [])
            self.assertTrue(st.file_issues)

    def test_header_only_file_is_valid_and_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        try:
            recs, st = pc.read_packets(tf.name)
            self.assertEqual((recs, st.file_issues), ([], []))
        finally:
            os.unlink(tf.name)

    def test_absurd_caplen_stops_cleanly(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            tf.write(struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 0x7FFFFFFF))
        try:
            recs, st = pc.read_packets(tf.name)
            self.assertEqual(recs, [])
            self.assertTrue(any("implausible" in i for i in st.file_issues))
        finally:
            os.unlink(tf.name)

    def test_random_garbage_never_crashes(self):
        import random
        rnd = random.Random(1234)
        for _ in range(300):
            rec = pc.PacketRecord(packet_no=1)
            blob = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 120)))
            lt = rnd.choice([0, 1, 101, 113, 228, 229, 999])
            pc.parse_packet(blob, lt, rec)       # must not raise
            self.assertIn(rec.parse_status, ("ok", "partial", "malformed"))


class OtherFormats(unittest.TestCase):
    def test_raw_ip(self):
        recs, st = pc.read_packets(S("raw_ip.pcap"))
        self.assertEqual((len(recs), st.link_type), (4, 101))
        self.assertEqual(recs[3].protocol, "UDP")

    def test_linux_cooked(self):
        recs, _ = pc.read_packets(S("linux_cooked.pcap"))
        self.assertEqual([r.dst_port for r in recs], [3306, 33000, 123])

    def test_pcapng(self):
        recs, st = pc.read_packets(S("sample.pcapng"))
        self.assertEqual(st.format, "pcapng")
        self.assertEqual(len(recs), 3)
        self.assertAlmostEqual(recs[1].timestamp, ms.T0 + 1, places=5)

    def test_big_endian_pcap(self):
        frame = ms.eth(ms.MAC_B, ms.MAC_A, 0x0800,
                       ms.ipv4("1.2.3.4", "5.6.7.8", 17, ms.udp(1000, 2000)))
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            tf.write(struct.pack(">IIII", 1_700_000_000, 500_000, len(frame), len(frame)))
            tf.write(frame)
        try:
            recs, _ = pc.read_packets(tf.name)
            self.assertEqual((recs[0].src_port, recs[0].dst_ip), (1000, "5.6.7.8"))
            self.assertAlmostEqual(recs[0].timestamp, 1_700_000_000.5)
        finally:
            os.unlink(tf.name)

    def test_nanosecond_pcap(self):
        frame = ms.eth(ms.MAC_B, ms.MAC_A, 0x0800,
                       ms.ipv4("1.2.3.4", "5.6.7.8", 17, ms.udp(1, 2)))
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
            tf.write(struct.pack("<IIII", 10, 250_000_000, len(frame), len(frame)))
            tf.write(frame)
        try:
            recs, st = pc.read_packets(tf.name)
            self.assertEqual(st.format, "pcap-nsec")
            self.assertAlmostEqual(recs[0].timestamp, 10.25)
        finally:
            os.unlink(tf.name)


class OutputsAndLiveGuard(unittest.TestCase):
    def test_csv_and_json_round_trip(self):
        import csv, json
        recs, st = pc.read_packets(S("malformed_packets.pcap"))
        with tempfile.TemporaryDirectory() as d:
            pc.write_csv(os.path.join(d, "o.csv"), recs)
            pc.write_json(os.path.join(d, "o.json"), recs, st)
            with open(os.path.join(d, "o.csv")) as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 16)
            self.assertEqual(rows[1]["src_ip"], "")           # missing -> empty
            self.assertEqual(rows[0]["dst_port"], "80")
            with open(os.path.join(d, "o.json")) as fh:
                js = json.load(fh)
            self.assertEqual(js["packet_count"], 16)
            self.assertIsNone(js["packets"][1]["src_ip"])

    def test_pcap_writer_round_trip(self):
        pk = ms.normal_packets()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rt.pcap")
            self.assertEqual(pc.write_pcap(path, pk), 16)
            recs, _ = pc.read_packets(path)
            self.assertEqual(len(recs), 16)

    def test_live_capture_requires_authorization(self):
        with self.assertRaises(pc.AuthorizationError):
            pc.live_capture("lo", authorized=False)
        with self.assertRaises(pc.AuthorizationError):
            pc.live_capture("eth9", authorized=True, allow_list=["lo"])

    def test_cli_returns_error_code_when_unauthorized(self):
        self.assertEqual(pc.main(["capture", "-i", "lo", "-c", "1", "--quiet"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
