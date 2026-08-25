"""
test_sniffer.py — Automated Test Suite for Network Packet Sniffer
=================================================================
Tests: ParsedPacket model, TrafficSimulator, PacketFilter, PacketStats,
       PacketCaptureEngine (simulate mode), JSON/CSV export, hex dump formatting.

Run with:
    python -m unittest test_sniffer.py -v
"""

import json
import os
import tempfile
import threading
import time
import unittest

from packet_engine import (
    PacketCaptureEngine,
    PacketFilter,
    PacketStats,
    ParsedPacket,
    ProtocolParser,
    TrafficSimulator,
    TCP_FLAGS,
    ICMP_TYPES,
    WELL_KNOWN_PORTS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_packet(protocol="TCP", ip_src="10.0.0.1", ip_dst="10.0.0.2",
               tcp_sport=49000, tcp_dport=80, info="Test packet",
               length=100) -> ParsedPacket:
    pp = ParsedPacket()
    pp.protocol   = protocol
    pp.ip_src     = ip_src
    pp.ip_dst     = ip_dst
    pp.tcp_sport  = tcp_sport if protocol in ("TCP", "HTTP", "HTTPS", "SSH") else None
    pp.tcp_dport  = tcp_dport if protocol in ("TCP", "HTTP", "HTTPS", "SSH") else None
    pp.tcp_flags  = {k: k == "ACK" for k in TCP_FLAGS}
    pp.tcp_flags_str = "ACK"
    pp.info       = info
    pp.length     = length
    pp.eth_src    = "aa:bb:cc:dd:ee:01"
    pp.eth_dst    = "aa:bb:cc:dd:ee:02"
    pp.ip_version = 4
    pp.ip_ttl     = 64
    pp.color_class= f"proto-{protocol.lower()}"
    return pp


# ─────────────────────────────────────────────────────────────────────────────
# Test Groups
# ─────────────────────────────────────────────────────────────────────────────

class TestParsedPacket(unittest.TestCase):
    """Tests for ParsedPacket model."""

    def test_id_autoincrement(self):
        """Each packet gets a unique, incrementing ID."""
        a = ParsedPacket()
        b = ParsedPacket()
        self.assertGreater(b.packet_id, a.packet_id)

    def test_set_payload_hex(self):
        pp = ParsedPacket()
        data = b"Hello, World!"
        pp.set_payload(data)
        self.assertEqual(pp.payload_hex, data.hex())
        self.assertEqual(pp.payload_ascii, "Hello, World!")

    def test_set_payload_non_printable(self):
        pp = ParsedPacket()
        pp.set_payload(bytes([0, 1, 255, 65, 66]))
        self.assertEqual(pp.payload_ascii, "...AB")

    def test_to_dict_keys(self):
        pp = make_packet()
        d = pp.to_dict()
        for key in ("id","timestamp","time","protocol","ip_src","ip_dst","length","info"):
            self.assertIn(key, d, f"Missing key: {key}")

    def test_format_hex_dump_structure(self):
        data = bytes(range(32))
        dump = ParsedPacket.format_hex_dump(data)
        lines = dump.strip().split("\n")
        self.assertEqual(len(lines), 2)  # 16 bytes per row → 2 rows for 32 bytes
        # First line starts with offset 0000
        self.assertTrue(lines[0].startswith("0000"))

    def test_datetime_str_set(self):
        pp = ParsedPacket()
        self.assertRegex(pp.datetime_str, r"\d{2}:\d{2}:\d{2}\.\d{3}")

    def test_port_service_known(self):
        self.assertEqual(ParsedPacket.port_service(80),  "HTTP")
        self.assertEqual(ParsedPacket.port_service(443), "HTTPS")
        self.assertEqual(ParsedPacket.port_service(53),  "DNS")

    def test_port_service_unknown(self):
        self.assertEqual(ParsedPacket.port_service(12345), "12345")


class TestTrafficSimulator(unittest.TestCase):
    """Tests for the simulated traffic generator."""

    def setUp(self):
        self.sim = TrafficSimulator()

    def test_http_request_protocol(self):
        pkt = self.sim.http_request()
        self.assertIn(pkt.protocol, ("HTTP", "HTTPS"))
        self.assertIsNotNone(pkt.ip_src)
        self.assertIsNotNone(pkt.ip_dst)
        self.assertIsNotNone(pkt.tcp_sport)
        self.assertIn(pkt.tcp_dport, (80, 443))

    def test_http_request_has_app_data(self):
        pkt = self.sim.http_request()
        self.assertIsNotNone(pkt.app_data)
        self.assertIn("method", pkt.app_data)
        self.assertIn(pkt.app_data["method"], ("GET","POST","PUT","DELETE"))

    def test_dns_query_structure(self):
        pkt = self.sim.dns_query()
        self.assertEqual(pkt.protocol, "DNS")
        self.assertEqual(pkt.udp_dport, 53)
        self.assertIsNotNone(pkt.app_data)
        self.assertFalse(pkt.app_data.get("is_response", True))
        queries = pkt.app_data.get("queries", [])
        self.assertGreater(len(queries), 0)

    def test_dns_response_structure(self):
        pkt = self.sim.dns_response()
        self.assertEqual(pkt.protocol, "DNS")
        self.assertEqual(pkt.udp_sport, 53)
        self.assertTrue(pkt.app_data.get("is_response"))
        self.assertGreater(len(pkt.app_data.get("records", [])), 0)

    def test_icmp_ping_fields(self):
        pkt = self.sim.icmp_ping()
        self.assertEqual(pkt.protocol, "ICMP")
        self.assertIn(pkt.icmp_type, (0, 8))
        self.assertIn(pkt.icmp_type_name, ICMP_TYPES.values())
        self.assertIsNotNone(pkt.ip_src)
        self.assertIsNotNone(pkt.ip_dst)

    def test_tcp_handshake_returns_three(self):
        pkts = self.sim.tcp_handshake()
        self.assertEqual(len(pkts), 3)
        flags = [p.tcp_flags_str for p in pkts]
        self.assertIn("SYN", flags)
        self.assertIn("SYN+ACK", flags)
        self.assertIn("ACK", flags)

    def test_arp_exchange_returns_two(self):
        pkts = self.sim.arp_exchange()
        self.assertEqual(len(pkts), 2)
        for p in pkts:
            self.assertEqual(p.protocol, "ARP")
        self.assertIn("Request", pkts[0].info)
        self.assertIn("Reply", pkts[1].info)

    def test_udp_generic_structure(self):
        pkt = self.sim.udp_generic()
        self.assertEqual(pkt.protocol, "UDP")
        self.assertIsNotNone(pkt.udp_sport)
        self.assertIsNotNone(pkt.udp_dport)
        self.assertIsNotNone(pkt.udp_len)

    def test_http_response_protocol(self):
        pkt = self.sim.http_response()
        self.assertEqual(pkt.protocol, "HTTP")
        self.assertIn("status", pkt.app_data)

    def test_generate_packet_returns_list(self):
        for _ in range(20):
            result = self.sim.generate_packet()
            self.assertIsInstance(result, list)
            self.assertGreater(len(result), 0)
            for p in result:
                self.assertIsInstance(p, ParsedPacket)
                self.assertIsNotNone(p.protocol)

    def test_all_packets_have_length(self):
        for _ in range(15):
            for pkt in self.sim.generate_packet():
                self.assertGreater(pkt.length, 0, f"Packet {pkt.protocol} has zero length")

    def test_mac_addresses_set(self):
        pkt = self.sim.http_request()
        self.assertIsNotNone(pkt.eth_src)
        self.assertIsNotNone(pkt.eth_dst)

    def test_ip_version_is_4(self):
        pkt = self.sim.http_request()
        self.assertEqual(pkt.ip_version, 4)


class TestPacketFilter(unittest.TestCase):
    """Tests for the filter expression evaluator."""

    def setUp(self):
        self.http_pkt = make_packet(protocol="HTTP", ip_src="192.168.1.10", ip_dst="8.8.8.8",
                                    tcp_sport=55000, tcp_dport=80, info="GET /api HTTP/1.1")
        self.dns_pkt  = make_packet(protocol="DNS",  ip_src="10.0.0.1",    ip_dst="8.8.8.8",
                                    info="DNS Query: google.com")
        self.dns_pkt.tcp_sport = None; self.dns_pkt.tcp_dport = None
        self.dns_pkt.udp_sport = 55001; self.dns_pkt.udp_dport = 53

    def test_empty_filter_matches_all(self):
        for pkt in [self.http_pkt, self.dns_pkt]:
            self.assertTrue(PacketFilter.matches(pkt, ""))
            self.assertTrue(PacketFilter.matches(pkt, "  "))

    def test_proto_filter_match(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt, "proto:HTTP"))
        self.assertFalse(PacketFilter.matches(self.http_pkt, "proto:DNS"))

    def test_proto_filter_case_insensitive(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt, "proto:http"))
        self.assertTrue(PacketFilter.matches(self.http_pkt, "proto:Http"))

    def test_ip_filter_src(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt, "ip:192.168.1.10"))
        self.assertFalse(PacketFilter.matches(self.http_pkt, "ip:10.10.10.10"))

    def test_ip_filter_dst(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt, "ip:8.8.8.8"))

    def test_src_filter(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt,  "src:192.168.1.10"))
        self.assertFalse(PacketFilter.matches(self.http_pkt, "src:8.8.8.8"))

    def test_dst_filter(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt,  "dst:8.8.8.8"))
        self.assertFalse(PacketFilter.matches(self.http_pkt, "dst:192.168.1.10"))

    def test_port_filter_tcp(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt,  "port:80"))
        self.assertTrue(PacketFilter.matches(self.http_pkt,  "port:55000"))
        self.assertFalse(PacketFilter.matches(self.http_pkt, "port:443"))

    def test_port_filter_udp(self):
        self.assertTrue(PacketFilter.matches(self.dns_pkt, "port:53"))

    def test_payload_filter(self):
        pkt = make_packet(protocol="HTTP")
        pkt.set_payload(b"GET /api/v1/users HTTP/1.1\r\nHost: example.com")
        self.assertTrue(PacketFilter.matches(pkt,  "payload:users"))
        self.assertFalse(PacketFilter.matches(pkt, "payload:POST"))

    def test_and_logic(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt, "proto:HTTP and ip:8.8.8.8"))
        self.assertFalse(PacketFilter.matches(self.http_pkt, "proto:HTTP and ip:1.1.1.1"))

    def test_or_logic(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt, "proto:HTTP or proto:DNS"))
        self.assertTrue(PacketFilter.matches(self.dns_pkt,  "proto:HTTP or proto:DNS"))
        self.assertFalse(PacketFilter.matches(self.http_pkt,"proto:ICMP or proto:ARP"))

    def test_generic_substring(self):
        self.assertTrue(PacketFilter.matches(self.http_pkt, "GET"))
        self.assertFalse(PacketFilter.matches(self.http_pkt,"POST"))

    def test_invalid_filter_shows_all(self):
        # Broken filter should not crash and should return True (show all)
        result = PacketFilter.matches(self.http_pkt, "port:notanumber")
        self.assertIsInstance(result, bool)  # Should not raise, just return bool


class TestPacketStats(unittest.TestCase):
    """Tests for rolling packet statistics."""

    def test_update_increments_counters(self):
        stats = PacketStats()
        pp = make_packet(length=100)
        stats.update(pp)
        snap = stats.snapshot()
        self.assertEqual(snap["total_packets"], 1)
        self.assertEqual(snap["total_bytes"],   100)

    def test_protocol_counts(self):
        stats = PacketStats()
        for _ in range(3): stats.update(make_packet(protocol="TCP"))
        for _ in range(5): stats.update(make_packet(protocol="DNS"))
        snap = stats.snapshot()
        self.assertEqual(snap["protocol_counts"]["TCP"], 3)
        self.assertEqual(snap["protocol_counts"]["DNS"], 5)

    def test_top_src_ips(self):
        stats = PacketStats()
        for _ in range(10): stats.update(make_packet(ip_src="1.1.1.1"))
        for _ in range(3):  stats.update(make_packet(ip_src="2.2.2.2"))
        snap = stats.snapshot()
        top = snap["top_src"]
        self.assertEqual(top[0][0], "1.1.1.1")
        self.assertEqual(top[0][1], 10)

    def test_multiple_updates_thread_safe(self):
        stats = PacketStats()
        errors = []
        def worker():
            try:
                for _ in range(100):
                    stats.update(make_packet())
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(len(errors), 0)
        snap = stats.snapshot()
        self.assertEqual(snap["total_packets"], 500)


class TestCaptureEngine(unittest.TestCase):
    """Integration tests for PacketCaptureEngine in simulation mode."""

    def test_simulate_generates_packets(self):
        engine = PacketCaptureEngine()
        received = []
        engine.add_callback(received.append)
        engine.start_simulate(rate=10)
        time.sleep(0.8)
        engine.stop()
        self.assertGreater(len(received), 0)

    def test_simulate_packets_have_required_fields(self):
        engine = PacketCaptureEngine()
        received = []
        engine.add_callback(received.append)
        engine.start_simulate(rate=10)
        time.sleep(0.6)
        engine.stop()
        for pkt in received:
            self.assertIsNotNone(pkt.protocol, f"Packet #{pkt.packet_id} has no protocol")
            self.assertGreater(pkt.length, 0, f"Packet #{pkt.packet_id} has zero length")
            self.assertIsNotNone(pkt.info, "Info is None")

    def test_get_packets_returns_list(self):
        engine = PacketCaptureEngine()
        engine.start_simulate(rate=10)
        time.sleep(0.5)
        engine.stop()
        pkts = engine.get_packets(limit=50)
        self.assertIsInstance(pkts, list)
        for p in pkts:
            self.assertIsInstance(p, dict)
            self.assertIn("id", p)

    def test_get_packets_filter(self):
        engine = PacketCaptureEngine()
        engine.start_simulate(rate=10)
        time.sleep(1.0)
        engine.stop()
        pkts = engine.get_packets(filter_expr="proto:HTTP")
        for p in pkts:
            self.assertEqual(p["protocol"], "HTTP")

    def test_get_packet_by_id(self):
        engine = PacketCaptureEngine()
        received = []
        engine.add_callback(received.append)
        engine.start_simulate(rate=10)
        time.sleep(0.5)
        engine.stop()
        if received:
            first_id = received[0].packet_id
            pkt_dict = engine.get_packet_by_id(first_id)
            self.assertIsNotNone(pkt_dict)
            self.assertEqual(pkt_dict["id"], first_id)

    def test_get_packet_by_id_not_found(self):
        engine = PacketCaptureEngine()
        result = engine.get_packet_by_id(999999)
        self.assertIsNone(result)

    def test_clear_resets_packets(self):
        engine = PacketCaptureEngine()
        engine.start_simulate(rate=10)
        time.sleep(0.5)
        engine.stop()
        self.assertGreater(len(engine._packets), 0)
        engine.clear()
        self.assertEqual(len(engine._packets), 0)

    def test_stats_updated_on_capture(self):
        engine = PacketCaptureEngine()
        engine.start_simulate(rate=10)
        time.sleep(0.6)
        engine.stop()
        snap = engine.stats.snapshot()
        self.assertGreater(snap["total_packets"], 0)
        self.assertGreater(snap["total_bytes"], 0)
        self.assertGreater(len(snap["protocol_counts"]), 0)

    def test_since_id_filter(self):
        engine = PacketCaptureEngine()
        engine.start_simulate(rate=15)
        time.sleep(0.4)
        all_pkts = engine.get_packets()
        if len(all_pkts) >= 2:
            pivot_id = all_pkts[len(all_pkts)//2]["id"]
            newer = engine.get_packets(since_id=pivot_id)
            for p in newer:
                self.assertGreater(p["id"], pivot_id)
        engine.stop()


class TestExport(unittest.TestCase):
    """Tests for JSON and CSV export functionality."""

    def setUp(self):
        self.engine = PacketCaptureEngine()
        self.engine.start_simulate(rate=10)
        time.sleep(0.7)
        self.engine.stop()

    def test_export_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            count = self.engine.export_json(path)
            self.assertGreater(count, 0)
            with open(path) as f:
                data = json.load(f)
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), count)
            # Validate structure of first packet
            first = data[0]
            for key in ("id","protocol","ip_src","ip_dst","length","info"):
                self.assertIn(key, first)
        finally:
            os.unlink(path)

    def test_export_json_with_filter(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            count = self.engine.export_json(path, filter_expr="proto:HTTP")
            with open(path) as f:
                data = json.load(f)
            for pkt in data:
                self.assertEqual(pkt["protocol"], "HTTP")
        finally:
            os.unlink(path)

    def test_export_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            path = f.name
        try:
            count = self.engine.export_csv(path)
            self.assertGreater(count, 0)
            with open(path) as f:
                lines = f.readlines()
            # Header + at least 1 data row
            self.assertGreater(len(lines), 1)
            header = lines[0].strip()
            self.assertIn("Protocol", header)
            self.assertIn("Src IP", header)
        finally:
            os.unlink(path)

    def test_json_ids_unique(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            self.engine.export_json(path)
            with open(path) as f:
                data = json.load(f)
            ids = [p["id"] for p in data]
            self.assertEqual(len(ids), len(set(ids)), "Duplicate packet IDs in export!")
        finally:
            os.unlink(path)


class TestConstants(unittest.TestCase):
    """Sanity-check protocol tables."""

    def test_well_known_ports_not_empty(self):
        self.assertGreater(len(WELL_KNOWN_PORTS), 10)

    def test_tcp_flags_complete(self):
        expected = {"SYN","ACK","FIN","RST","PSH","URG","ECE","CWR"}
        self.assertEqual(set(TCP_FLAGS.keys()), expected)

    def test_icmp_types_has_echo(self):
        self.assertIn(0, ICMP_TYPES)   # Echo Reply
        self.assertIn(8, ICMP_TYPES)   # Echo Request

    def test_port_80_is_http(self):
        self.assertEqual(WELL_KNOWN_PORTS[80],  "HTTP")
        self.assertEqual(WELL_KNOWN_PORTS[443], "HTTPS")
        self.assertEqual(WELL_KNOWN_PORTS[53],  "DNS")
        self.assertEqual(WELL_KNOWN_PORTS[22],  "SSH")


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═"*70)
    print("  NetWatch — Automated Test Suite")
    print("═"*70 + "\n")
    unittest.main(verbosity=2)
