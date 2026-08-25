"""
packet_engine.py — Core Network Packet Capture & Analysis Engine
================================================================
Supports:
  - Live packet capture via Scapy (requires Npcap / Admin on Windows)
  - Simulated network traffic for learning without elevated privileges
  - Deep protocol analysis: Ethernet, IP, IPv6, TCP, UDP, ICMP, DNS, HTTP
  - PCAP & JSON export
  - BPF-style filter evaluation
"""

from __future__ import annotations

import json
import os
import random
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Dict, List, Optional

# ── Optional Scapy import (graceful degradation) ────────────────────────────
try:
    from scapy.all import (
        ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, IPv6,
        Raw, TCP, UDP, conf, get_if_list, rdpcap, sniff, wrpcap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Protocol Numbers & Constants
# ─────────────────────────────────────────────────────────────────────────────

PROTO_NAMES: Dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

WELL_KNOWN_PORTS: Dict[int, str] = {
    20:   "FTP-DATA", 21:  "FTP",   22:  "SSH",   23:  "TELNET",
    25:   "SMTP",     53:  "DNS",   67:  "DHCP",   68:  "DHCP",
    69:   "TFTP",     80:  "HTTP",  110: "POP3",   123: "NTP",
    143:  "IMAP",     161: "SNMP",  194: "IRC",    443: "HTTPS",
    445:  "SMB",      3306:"MySQL", 3389:"RDP",    5353:"mDNS",
    8080: "HTTP-ALT", 8443:"HTTPS-ALT",
}

TCP_FLAGS: Dict[str, int] = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04,
    "PSH": 0x08, "ACK": 0x10, "URG": 0x20,
    "ECE": 0x40, "CWR": 0x80,
}

ICMP_TYPES: Dict[int, str] = {
    0:  "Echo Reply",     3:  "Destination Unreachable",
    4:  "Source Quench",  5:  "Redirect",
    8:  "Echo Request",   11: "Time Exceeded",
    12: "Parameter Problem", 13: "Timestamp",
    14: "Timestamp Reply",
}

# ─────────────────────────────────────────────────────────────────────────────
# Parsed Packet Model
# ─────────────────────────────────────────────────────────────────────────────

class ParsedPacket:
    """Structured representation of a captured/simulated network packet."""

    _id_counter = 0
    _lock = threading.Lock()

    def __init__(self):
        with ParsedPacket._lock:
            ParsedPacket._id_counter += 1
            self.packet_id: int = ParsedPacket._id_counter

        self.timestamp: float = time.time()
        self.datetime_str: str = datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]
        self.length: int = 0

        # Layer 2 — Ethernet
        self.eth_src: Optional[str] = None
        self.eth_dst: Optional[str] = None
        self.eth_type: Optional[str] = None

        # Layer 3 — IP
        self.ip_src: Optional[str] = None
        self.ip_dst: Optional[str] = None
        self.ip_version: Optional[int] = None
        self.ip_ttl: Optional[int] = None
        self.ip_proto: Optional[int] = None
        self.ip_proto_name: Optional[str] = None
        self.ip_hdr_len: Optional[int] = None
        self.ip_checksum: Optional[str] = None
        self.ip_flags: Optional[str] = None
        self.ip_frag_offset: Optional[int] = None

        # Layer 4 — TCP
        self.tcp_sport: Optional[int] = None
        self.tcp_dport: Optional[int] = None
        self.tcp_flags: Optional[Dict[str, bool]] = None
        self.tcp_flags_str: Optional[str] = None
        self.tcp_seq: Optional[int] = None
        self.tcp_ack: Optional[int] = None
        self.tcp_window: Optional[int] = None
        self.tcp_checksum: Optional[str] = None

        # Layer 4 — UDP
        self.udp_sport: Optional[int] = None
        self.udp_dport: Optional[int] = None
        self.udp_len: Optional[int] = None
        self.udp_checksum: Optional[str] = None

        # Layer 4 — ICMP
        self.icmp_type: Optional[int] = None
        self.icmp_type_name: Optional[str] = None
        self.icmp_code: Optional[int] = None

        # Layer 7 — Application
        self.app_protocol: Optional[str] = None
        self.app_data: Optional[Dict] = None

        # Payload
        self.raw_payload: Optional[bytes] = None
        self.payload_hex: Optional[str] = None
        self.payload_ascii: Optional[str] = None

        # Display
        self.protocol: str = "UNKNOWN"
        self.info: str = ""
        self.color_class: str = "proto-unknown"

    # ── Service port helper ──────────────────────────────────────────────────
    @staticmethod
    def port_service(port: int) -> str:
        return WELL_KNOWN_PORTS.get(port, str(port))

    # ── Hex dump formatter ───────────────────────────────────────────────────
    @staticmethod
    def format_hex_dump(data: bytes, bytes_per_row: int = 16) -> str:
        if not data:
            return ""
        rows = []
        for i in range(0, len(data), bytes_per_row):
            chunk = data[i:i + bytes_per_row]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            rows.append(f"{i:04X}  {hex_part:<{bytes_per_row*3}}  {ascii_part}")
        return "\n".join(rows)

    def set_payload(self, raw: bytes):
        """Store raw payload and generate hex/ascii representations."""
        self.raw_payload = raw
        self.payload_hex = raw.hex() if raw else ""
        self.payload_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in (raw or b""))

    def to_dict(self) -> dict:
        """Serialise the packet to a JSON-safe dictionary."""
        d = {
            "id":             self.packet_id,
            "timestamp":      self.timestamp,
            "time":           self.datetime_str,
            "length":         self.length,
            "protocol":       self.protocol,
            "info":           self.info,
            "color_class":    self.color_class,
            # Ethernet
            "eth_src":        self.eth_src,
            "eth_dst":        self.eth_dst,
            "eth_type":       self.eth_type,
            # IP
            "ip_src":         self.ip_src,
            "ip_dst":         self.ip_dst,
            "ip_version":     self.ip_version,
            "ip_ttl":         self.ip_ttl,
            "ip_proto":       self.ip_proto,
            "ip_proto_name":  self.ip_proto_name,
            "ip_hdr_len":     self.ip_hdr_len,
            "ip_checksum":    self.ip_checksum,
            "ip_flags":       self.ip_flags,
            # TCP
            "tcp_sport":      self.tcp_sport,
            "tcp_dport":      self.tcp_dport,
            "tcp_flags":      self.tcp_flags,
            "tcp_flags_str":  self.tcp_flags_str,
            "tcp_seq":        self.tcp_seq,
            "tcp_ack":        self.tcp_ack,
            "tcp_window":     self.tcp_window,
            # UDP
            "udp_sport":      self.udp_sport,
            "udp_dport":      self.udp_dport,
            "udp_len":        self.udp_len,
            # ICMP
            "icmp_type":      self.icmp_type,
            "icmp_type_name": self.icmp_type_name,
            "icmp_code":      self.icmp_code,
            # Application
            "app_protocol":   self.app_protocol,
            "app_data":       self.app_data,
            # Payload
            "payload_hex":    self.payload_hex,
            "payload_ascii":  self.payload_ascii,
        }
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Protocol Parsers
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolParser:
    """Parses Scapy packets into ParsedPacket objects."""

    @staticmethod
    def parse(scapy_pkt) -> ParsedPacket:
        pp = ParsedPacket()
        pp.length = len(scapy_pkt)

        # ── Ethernet ────────────────────────────────────────────────────────
        if scapy_pkt.haslayer(Ether):
            eth = scapy_pkt[Ether]
            pp.eth_src = eth.src
            pp.eth_dst = eth.dst
            pp.eth_type = hex(eth.type)

        # ── IP / IPv6 ───────────────────────────────────────────────────────
        if scapy_pkt.haslayer(IP):
            ip = scapy_pkt[IP]
            pp.ip_src       = ip.src
            pp.ip_dst       = ip.dst
            pp.ip_version   = ip.version
            pp.ip_ttl       = ip.ttl
            pp.ip_proto     = ip.proto
            pp.ip_proto_name= PROTO_NAMES.get(ip.proto, str(ip.proto))
            pp.ip_hdr_len   = ip.ihl * 4
            pp.ip_checksum  = hex(ip.chksum) if ip.chksum else None
            pp.ip_flags     = str(ip.flags)
            pp.ip_frag_offset = ip.frag

        elif scapy_pkt.haslayer(IPv6):
            ip6 = scapy_pkt[IPv6]
            pp.ip_src      = ip6.src
            pp.ip_dst      = ip6.dst
            pp.ip_version  = 6
            pp.ip_ttl      = ip6.hlim
            pp.ip_proto    = ip6.nh
            pp.ip_proto_name = PROTO_NAMES.get(ip6.nh, str(ip6.nh))

        # ── TCP ─────────────────────────────────────────────────────────────
        if scapy_pkt.haslayer(TCP):
            tcp = scapy_pkt[TCP]
            pp.tcp_sport   = tcp.sport
            pp.tcp_dport   = tcp.dport
            pp.tcp_seq     = tcp.seq
            pp.tcp_ack     = tcp.ack
            pp.tcp_window  = tcp.window
            pp.tcp_checksum= hex(tcp.chksum) if tcp.chksum else None
            flags_int      = int(tcp.flags)
            pp.tcp_flags   = {name: bool(flags_int & val) for name, val in TCP_FLAGS.items()}
            pp.tcp_flags_str = tcp.flags.__str__() if hasattr(tcp.flags, '__str__') else str(tcp.flags)
            active = [k for k, v in pp.tcp_flags.items() if v]
            pp.tcp_flags_str = "+".join(active) if active else "NONE"

            # Detect HTTP
            raw_layer = tcp.payload
            if raw_layer and hasattr(raw_layer, 'load'):
                payload = raw_layer.load
                pp.set_payload(payload)
                http_data = ProtocolParser._parse_http(payload)
                if http_data:
                    pp.app_protocol = "HTTP"
                    pp.app_data     = http_data

            port = tcp.dport if tcp.dport in WELL_KNOWN_PORTS else tcp.sport
            if pp.app_protocol == "HTTP":
                pp.protocol    = "HTTP"
                pp.color_class = "proto-http"
                method = pp.app_data.get("method", "")
                uri    = pp.app_data.get("uri", "")
                status = pp.app_data.get("status", "")
                pp.info = f"{method} {uri}" if method else f"HTTP {status}"
            elif tcp.dport == 443 or tcp.sport == 443:
                pp.protocol    = "HTTPS"
                pp.color_class = "proto-https"
                pp.info = f"{pp.ip_src}:{tcp.sport} → {pp.ip_dst}:{tcp.dport} [TLS]"
            elif tcp.dport == 22 or tcp.sport == 22:
                pp.protocol    = "SSH"
                pp.color_class = "proto-ssh"
                pp.info = f"SSH {pp.ip_src}:{tcp.sport} → {pp.ip_dst}:{tcp.dport}"
            else:
                pp.protocol    = "TCP"
                pp.color_class = "proto-tcp"
                service = WELL_KNOWN_PORTS.get(port, "")
                svc_str= f" ({service})" if service else ""
                pp.info = (f"{pp.ip_src}:{tcp.sport} → {pp.ip_dst}:{tcp.dport}"
                           f"{svc_str} [{pp.tcp_flags_str}] Seq={tcp.seq}")

        # ── UDP ─────────────────────────────────────────────────────────────
        elif scapy_pkt.haslayer(UDP):
            udp = scapy_pkt[UDP]
            pp.udp_sport   = udp.sport
            pp.udp_dport   = udp.dport
            pp.udp_len     = udp.len
            pp.udp_checksum= hex(udp.chksum) if udp.chksum else None

            # DNS
            if scapy_pkt.haslayer(DNS):
                dns = scapy_pkt[DNS]
                dns_data = ProtocolParser._parse_dns(dns)
                pp.app_protocol = "DNS"
                pp.app_data     = dns_data
                pp.protocol     = "DNS"
                pp.color_class  = "proto-dns"
                qname = dns_data.get("queries", [{}])[0].get("name", "") if dns_data.get("queries") else ""
                qr    = "Response" if dns.qr else "Query"
                pp.info = f"DNS {qr}: {qname}"
            elif udp.dport == 67 or udp.sport == 68:
                pp.protocol    = "DHCP"
                pp.color_class = "proto-udp"
                pp.info = f"DHCP {'Request' if udp.dport==67 else 'Reply'}"
            elif udp.dport == 123 or udp.sport == 123:
                pp.protocol    = "NTP"
                pp.color_class = "proto-udp"
                pp.info = "NTP Time Sync"
            else:
                pp.protocol    = "UDP"
                pp.color_class = "proto-udp"
                service = WELL_KNOWN_PORTS.get(udp.dport, WELL_KNOWN_PORTS.get(udp.sport, ""))
                svc_str= f" ({service})" if service else ""
                pp.info = f"{pp.ip_src}:{udp.sport} → {pp.ip_dst}:{udp.dport}{svc_str} Len={udp.len}"

            if not pp.raw_payload and udp.payload and hasattr(udp.payload, 'load'):
                pp.set_payload(udp.payload.load)

        # ── ICMP ────────────────────────────────────────────────────────────
        elif scapy_pkt.haslayer(ICMP):
            icmp = scapy_pkt[ICMP]
            pp.icmp_type      = icmp.type
            pp.icmp_type_name = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
            pp.icmp_code      = icmp.code
            pp.protocol       = "ICMP"
            pp.color_class    = "proto-icmp"
            pp.info = (f"ICMP {pp.icmp_type_name} (type={icmp.type}, code={icmp.code})"
                       f" {pp.ip_src} → {pp.ip_dst}")

        # ── ARP ─────────────────────────────────────────────────────────────
        elif scapy_pkt.haslayer(ARP):
            arp = scapy_pkt[ARP]
            op  = "Request" if arp.op == 1 else "Reply"
            pp.protocol    = "ARP"
            pp.color_class = "proto-arp"
            pp.ip_src      = arp.psrc
            pp.ip_dst      = arp.pdst
            pp.info = f"ARP {op}: Who has {arp.pdst}? Tell {arp.psrc}"

        # ── Fallback ────────────────────────────────────────────────────────
        if not pp.protocol or pp.protocol == "UNKNOWN":
            pp.protocol    = "RAW"
            pp.color_class = "proto-unknown"
            pp.info = f"Raw packet, {pp.length} bytes"

        return pp

    # ── HTTP parser ─────────────────────────────────────────────────────────
    @staticmethod
    def _parse_http(data: bytes) -> Optional[dict]:
        try:
            text = data.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if not lines:
                return None
            first = lines[0]
            result: dict = {"raw_headers": lines[:20]}
            # Request
            if any(first.startswith(m) for m in ("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH")):
                parts = first.split(" ", 2)
                result["method"]   = parts[0] if len(parts) > 0 else ""
                result["uri"]      = parts[1] if len(parts) > 1 else ""
                result["version"]  = parts[2] if len(parts) > 2 else ""
                result["type"]     = "request"
                for line in lines[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        result[k.lower().replace("-","_")] = v
                return result
            # Response
            if first.startswith("HTTP/"):
                parts = first.split(" ", 2)
                result["version"] = parts[0] if len(parts) > 0 else ""
                result["status"]  = parts[1] if len(parts) > 1 else ""
                result["reason"]  = parts[2] if len(parts) > 2 else ""
                result["type"]    = "response"
                return result
        except Exception:
            pass
        return None

    # ── DNS parser ──────────────────────────────────────────────────────────
    @staticmethod
    def _parse_dns(dns) -> dict:
        result: dict = {
            "transaction_id": dns.id,
            "is_response":    bool(dns.qr),
            "opcode":         dns.opcode,
            "flags":          {
                "AA": bool(dns.aa), "TC": bool(dns.tc),
                "RD": bool(dns.rd), "RA": bool(dns.ra),
            },
            "questions":  dns.qdcount,
            "answers":    dns.ancount,
            "queries":    [],
            "records":    [],
        }
        # Queries
        try:
            q = dns[DNSQR]
            while q:
                result["queries"].append({"name": q.qname.decode() if isinstance(q.qname, bytes) else q.qname, "type": q.qtype})
                q = q.payload if hasattr(q, 'payload') and isinstance(q.payload, DNSQR) else None
        except Exception:
            pass
        # Answers
        try:
            a = dns[DNSRR]
            while a:
                rdata = a.rdata if hasattr(a, 'rdata') else ""
                result["records"].append({"name": str(a.rrname), "type": a.type, "rdata": str(rdata)})
                a = a.payload if hasattr(a, 'payload') and isinstance(a.payload, DNSRR) else None
        except Exception:
            pass
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Traffic Simulator
# ─────────────────────────────────────────────────────────────────────────────

class TrafficSimulator:
    """
    Generates realistic simulated network packet streams for learning purposes.
    No admin privileges required. Does NOT send real packets.
    """

    HOSTS = [
        ("192.168.1.10", "a1:b2:c3:d4:e5:f0"),
        ("192.168.1.20", "a1:b2:c3:d4:e5:f1"),
        ("8.8.8.8",      "00:00:00:00:00:01"),
        ("1.1.1.1",      "00:00:00:00:00:02"),
        ("172.16.0.5",   "aa:bb:cc:dd:ee:01"),
        ("10.0.0.1",     "aa:bb:cc:dd:ee:02"),
    ]

    WEBSITES = [
        ("www.google.com",    "142.250.80.46"),
        ("www.github.com",    "140.82.114.4"),
        ("api.example.com",   "203.0.113.10"),
        ("cdn.cloudflare.net","104.16.0.100"),
        ("mail.server.net",   "198.51.100.5"),
    ]

    DNS_DOMAINS = ["google.com.", "github.com.", "cloudflare.com.", "youtube.com.", "example.org."]

    def __init__(self):
        self._seq_counter = random.randint(100000, 999999)

    def _next_seq(self):
        self._seq_counter += random.randint(1, 1500)
        return self._seq_counter

    def _make_base(self, src_ip: str, dst_ip: str, proto: str, length: int,
                   src_mac: str = "aa:bb:cc:dd:ee:ff",
                   dst_mac: str = "ff:ee:dd:cc:bb:aa") -> ParsedPacket:
        pp = ParsedPacket()
        pp.eth_src     = src_mac
        pp.eth_dst     = dst_mac
        pp.eth_type    = "0x0800"
        pp.ip_src      = src_ip
        pp.ip_dst      = dst_ip
        pp.ip_version  = 4
        pp.ip_ttl      = random.choice([64, 128, 255])
        pp.ip_hdr_len  = 20
        pp.ip_checksum = hex(random.randint(0x1000, 0xFFFF))
        pp.ip_flags    = "DF"
        pp.protocol    = proto
        pp.length      = length
        return pp

    # ── HTTP/HTTPS scenarios ─────────────────────────────────────────────────
    def http_request(self) -> ParsedPacket:
        src = random.choice(self.HOSTS[:2])
        dst = random.choice(self.WEBSITES)
        methods = ["GET", "POST", "PUT", "DELETE"]
        uris = ["/", "/api/v1/users", "/search?q=python", "/login", "/data/feed.json"]
        method = random.choice(methods)
        uri    = random.choice(uris)
        is_https = random.random() > 0.4

        body = ""
        if method == "POST":
            body = '{"user":"alice","token":"abc123"}'

        raw_http = (
            f"{method} {uri} HTTP/1.1\r\n"
            f"Host: {dst[0]}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: application/json, text/html\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode()

        dport = 443 if is_https else 80
        pp = self._make_base(src[0], dst[1], "HTTPS" if is_https else "HTTP",
                             len(raw_http) + 54, src[1])
        pp.ip_proto      = 6
        pp.ip_proto_name = "TCP"
        pp.tcp_sport     = random.randint(49152, 65535)
        pp.tcp_dport     = dport
        pp.tcp_seq       = self._next_seq()
        pp.tcp_ack       = self._next_seq()
        pp.tcp_window    = 65535
        active = ["ACK", "PSH"]
        pp.tcp_flags     = {k: (k in active) for k in TCP_FLAGS}
        pp.tcp_flags_str = "+".join(active)
        pp.app_protocol  = "HTTPS" if is_https else "HTTP"
        pp.app_data      = {"method": method, "uri": uri, "host": dst[0],
                            "type": "request", "version": "HTTP/1.1",
                            "encrypted": is_https}
        pp.set_payload(raw_http)
        pp.color_class   = "proto-https" if is_https else "proto-http"
        pp.info = f"{method} {uri} → {dst[0]}" + (" [TLS]" if is_https else "")
        return pp

    def http_response(self) -> ParsedPacket:
        dst = random.choice(self.HOSTS[:2])
        src = random.choice(self.WEBSITES)
        statuses = [("200", "OK"), ("404", "Not Found"), ("301", "Moved Permanently"),
                    ("500", "Internal Server Error"), ("204", "No Content")]
        code, reason = random.choice(statuses)
        body = '{"status":"ok","data":[1,2,3]}' if code == "200" else f"<html>{reason}</html>"
        raw_http = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Server: nginx/1.21\r\n"
            f"X-Request-Id: {random.randint(100000,999999)}\r\n\r\n{body}"
        ).encode()
        pp = self._make_base(src[1], dst[0], "HTTP", len(raw_http) + 54, dst[1])
        pp.ip_proto = 6; pp.ip_proto_name = "TCP"
        pp.tcp_sport = 80; pp.tcp_dport = random.randint(49152, 65535)
        pp.tcp_seq   = self._next_seq(); pp.tcp_ack = self._next_seq()
        pp.tcp_window= 65535
        active = ["ACK", "PSH"]
        pp.tcp_flags = {k: (k in active) for k in TCP_FLAGS}; pp.tcp_flags_str = "+".join(active)
        pp.app_protocol = "HTTP"; pp.app_data = {"type": "response", "status": code, "reason": reason}
        pp.set_payload(raw_http); pp.color_class = "proto-http"
        pp.info = f"HTTP {code} {reason} ← {src[0]}"
        return pp

    # ── DNS scenarios ─────────────────────────────────────────────────────────
    def dns_query(self) -> ParsedPacket:
        src = random.choice(self.HOSTS[:2])
        domain = random.choice(self.DNS_DOMAINS)
        raw_payload = bytes([0, random.randint(1, 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        pp = self._make_base(src[0], "8.8.8.8", "DNS", 60, src[1])
        pp.ip_proto = 17; pp.ip_proto_name = "UDP"
        pp.udp_sport = random.randint(49152, 65535); pp.udp_dport = 53
        pp.udp_len   = 40; pp.udp_checksum = hex(random.randint(0x1000, 0xFFFF))
        pp.app_protocol = "DNS"
        pp.app_data = {"transaction_id": random.randint(1, 65535), "is_response": False,
                       "queries": [{"name": domain, "type": 1}], "records": [], "questions": 1, "answers": 0}
        pp.set_payload(raw_payload); pp.color_class = "proto-dns"
        pp.info = f"DNS Query: {domain} (A record)"
        return pp

    def dns_response(self) -> ParsedPacket:
        dst = random.choice(self.HOSTS[:2])
        domain = random.choice(self.DNS_DOMAINS)
        ip_answer = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
        pp = self._make_base("8.8.8.8", dst[0], "DNS", 80, dst[1])
        pp.ip_proto = 17; pp.ip_proto_name = "UDP"
        pp.udp_sport = 53; pp.udp_dport = random.randint(49152, 65535)
        pp.udp_len = 60; pp.udp_checksum = hex(random.randint(0x1000, 0xFFFF))
        pp.app_protocol = "DNS"
        pp.app_data = {"transaction_id": random.randint(1, 65535), "is_response": True,
                       "queries": [{"name": domain, "type": 1}],
                       "records": [{"name": domain, "type": 1, "rdata": ip_answer}],
                       "questions": 1, "answers": 1}
        pp.set_payload(b'\x00' * 10); pp.color_class = "proto-dns"
        pp.info = f"DNS Response: {domain} → {ip_answer}"
        return pp

    # ── ICMP ping/pong ────────────────────────────────────────────────────────
    def icmp_ping(self) -> ParsedPacket:
        src = random.choice(self.HOSTS[:3])
        dst = random.choice(self.HOSTS)
        while dst[0] == src[0]:
            dst = random.choice(self.HOSTS)
        is_request = random.random() > 0.5
        icmp_type  = 8 if is_request else 0
        pp = self._make_base(src[0], dst[0], "ICMP", 74, src[1], dst[1])
        pp.ip_proto = 1; pp.ip_proto_name = "ICMP"
        pp.icmp_type      = icmp_type
        pp.icmp_type_name = ICMP_TYPES.get(icmp_type, "Unknown")
        pp.icmp_code      = 0
        pp.set_payload(bytes(range(32, 56))); pp.color_class = "proto-icmp"
        label = "Request" if is_request else "Reply"
        pp.info = f"ICMP Echo {label}: {src[0]} → {dst[0]}"
        return pp

    # ── TCP Handshake ─────────────────────────────────────────────────────────
    def tcp_handshake(self) -> List[ParsedPacket]:
        src = random.choice(self.HOSTS[:2])
        dst = random.choice(self.WEBSITES)
        sport = random.randint(49152, 65535)
        dport = random.choice([80, 443, 22, 3306])
        seq   = random.randint(1000000, 9000000)
        packets = []
        # SYN
        syn = self._make_base(src[0], dst[1], "TCP", 54, src[1])
        syn.ip_proto = 6; syn.ip_proto_name = "TCP"
        syn.tcp_sport = sport; syn.tcp_dport = dport
        syn.tcp_seq = seq; syn.tcp_ack = 0; syn.tcp_window = 65535
        syn.tcp_flags = {k: k == "SYN" for k in TCP_FLAGS}; syn.tcp_flags_str = "SYN"
        syn.info = f"TCP SYN: {src[0]}:{sport} → {dst[0]}:{dport}"; syn.color_class = "proto-tcp"
        packets.append(syn)
        # SYN-ACK
        srv_seq = random.randint(1000000, 9000000)
        sak = self._make_base(dst[1], src[0], "TCP", 54, src[1])
        sak.ip_proto = 6; sak.ip_proto_name = "TCP"
        sak.tcp_sport = dport; sak.tcp_dport = sport
        sak.tcp_seq = srv_seq; sak.tcp_ack = seq + 1; sak.tcp_window = 65535
        sak.tcp_flags = {k: k in ("SYN", "ACK") for k in TCP_FLAGS}; sak.tcp_flags_str = "SYN+ACK"
        sak.info = f"TCP SYN-ACK: {dst[0]}:{dport} → {src[0]}:{sport}"; sak.color_class = "proto-tcp"
        packets.append(sak)
        # ACK
        ack = self._make_base(src[0], dst[1], "TCP", 54, src[1])
        ack.ip_proto = 6; ack.ip_proto_name = "TCP"
        ack.tcp_sport = sport; ack.tcp_dport = dport
        ack.tcp_seq = seq + 1; ack.tcp_ack = srv_seq + 1; ack.tcp_window = 65535
        ack.tcp_flags = {k: k == "ACK" for k in TCP_FLAGS}; ack.tcp_flags_str = "ACK"
        ack.info = f"TCP ACK (3-way handshake complete)"; ack.color_class = "proto-tcp"
        packets.append(ack)
        return packets

    # ── ARP ───────────────────────────────────────────────────────────────────
    def arp_exchange(self) -> List[ParsedPacket]:
        src = random.choice(self.HOSTS[:2])
        dst = random.choice(self.HOSTS)
        packets = []
        req = ParsedPacket()
        req.protocol = "ARP"; req.color_class = "proto-arp"
        req.eth_src = src[1]; req.eth_dst = "ff:ff:ff:ff:ff:ff"; req.eth_type = "0x0806"
        req.ip_src = src[0]; req.ip_dst = dst[0]; req.length = 42
        req.info = f"ARP Request: Who has {dst[0]}? Tell {src[0]}"
        packets.append(req)
        rep = ParsedPacket()
        rep.protocol = "ARP"; rep.color_class = "proto-arp"
        rep.eth_src = dst[1]; rep.eth_dst = src[1]; rep.eth_type = "0x0806"
        rep.ip_src = dst[0]; rep.ip_dst = src[0]; rep.length = 42
        rep.info = f"ARP Reply: {dst[0]} is at {dst[1]}"
        packets.append(rep)
        return packets

    # ── UDP generic ───────────────────────────────────────────────────────────
    def udp_generic(self) -> ParsedPacket:
        src = random.choice(self.HOSTS)
        dst = random.choice(self.HOSTS)
        while dst[0] == src[0]:
            dst = random.choice(self.HOSTS)
        sport = random.randint(49152, 65535)
        dport = random.choice([123, 161, 5353, 1900])
        svc   = WELL_KNOWN_PORTS.get(dport, str(dport))
        data  = bytes(random.randint(0,255) for _ in range(random.randint(8, 64)))
        pp = self._make_base(src[0], dst[0], "UDP", len(data) + 42, src[1], dst[1])
        pp.ip_proto = 17; pp.ip_proto_name = "UDP"
        pp.udp_sport = sport; pp.udp_dport = dport
        pp.udp_len   = len(data) + 8; pp.udp_checksum = hex(random.randint(0x1000, 0xFFFF))
        pp.set_payload(data); pp.color_class = "proto-udp"
        pp.info = f"UDP {src[0]}:{sport} → {dst[0]}:{dport} ({svc}) Len={len(data)}"
        return pp

    # ── Main generator ────────────────────────────────────────────────────────
    def generate_packet(self) -> List[ParsedPacket]:
        roll = random.random()
        if roll < 0.28:
            return [self.http_request()]
        elif roll < 0.44:
            return [self.http_response()]
        elif roll < 0.56:
            return [self.dns_query()]
        elif roll < 0.65:
            return [self.dns_response()]
        elif roll < 0.76:
            return [self.icmp_ping()]
        elif roll < 0.85:
            return self.tcp_handshake()
        elif roll < 0.91:
            return self.arp_exchange()
        else:
            return [self.udp_generic()]


# ─────────────────────────────────────────────────────────────────────────────
# Packet Filter Engine
# ─────────────────────────────────────────────────────────────────────────────

class PacketFilter:
    """Evaluate user-defined filter expressions against ParsedPacket objects."""

    @staticmethod
    def matches(pp: ParsedPacket, filter_expr: str) -> bool:
        if not filter_expr or filter_expr.strip() == "":
            return True
        expr = filter_expr.strip().lower()
        try:
            return PacketFilter._eval(pp, expr)
        except Exception:
            return True  # On parse error, show all

    @staticmethod
    def _eval(pp: ParsedPacket, expr: str) -> bool:
        # OR logic
        if " or " in expr:
            return any(PacketFilter._eval(pp, part.strip()) for part in expr.split(" or "))
        # AND logic
        if " and " in expr:
            return all(PacketFilter._eval(pp, part.strip()) for part in expr.split(" and "))
        # Simple terms
        if expr.startswith("proto:") or expr.startswith("protocol:"):
            target = expr.split(":", 1)[1].strip().upper()
            return pp.protocol.upper() == target
        if expr.startswith("ip:") or expr.startswith("host:"):
            ip = expr.split(":", 1)[1].strip()
            return ip in (pp.ip_src or "") or ip in (pp.ip_dst or "")
        if expr.startswith("src:"):
            ip = expr.split(":", 1)[1].strip()
            return ip in (pp.ip_src or "")
        if expr.startswith("dst:"):
            ip = expr.split(":", 1)[1].strip()
            return ip in (pp.ip_dst or "")
        if expr.startswith("port:"):
            port = int(expr.split(":", 1)[1].strip())
            return port in (pp.tcp_sport, pp.tcp_dport, pp.udp_sport, pp.udp_dport)
        if expr.startswith("payload:"):
            kw = expr.split(":", 1)[1].strip()
            return kw in (pp.payload_ascii or "").lower()
        # Generic substring (search across info + protocol)
        return expr in (pp.info or "").lower() or expr in (pp.protocol or "").lower()


# ─────────────────────────────────────────────────────────────────────────────
# Packet Statistics Tracker
# ─────────────────────────────────────────────────────────────────────────────

class PacketStats:
    """Thread-safe rolling statistics for captured packets."""

    def __init__(self, window: int = 500):
        self._lock = threading.Lock()
        self.total_packets   = 0
        self.total_bytes     = 0
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.src_ip_counts:   Dict[str, int] = defaultdict(int)
        self.dst_ip_counts:   Dict[str, int] = defaultdict(int)
        self.throughput_history: deque = deque(maxlen=60)  # packets per second (last 60s)
        self._second_bucket  = 0
        self._current_second = int(time.time())

    def update(self, pp: ParsedPacket):
        with self._lock:
            self.total_packets += 1
            self.total_bytes   += pp.length
            self.protocol_counts[pp.protocol] += 1
            if pp.ip_src: self.src_ip_counts[pp.ip_src] += 1
            if pp.ip_dst: self.dst_ip_counts[pp.ip_dst] += 1
            now = int(time.time())
            if now != self._current_second:
                self.throughput_history.append({"t": self._current_second, "pps": self._second_bucket})
                self._second_bucket  = 0
                self._current_second = now
            self._second_bucket += 1

    def snapshot(self) -> dict:
        with self._lock:
            top_src = sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            top_dst = sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            return {
                "total_packets":    self.total_packets,
                "total_bytes":      self.total_bytes,
                "protocol_counts":  dict(self.protocol_counts),
                "top_src":          top_src,
                "top_dst":          top_dst,
                "throughput":       list(self.throughput_history),
            }


# ─────────────────────────────────────────────────────────────────────────────
# Main Capture Engine
# ─────────────────────────────────────────────────────────────────────────────

class PacketCaptureEngine:
    """
    Central engine orchestrating live capture (Scapy) OR simulation.
    Callbacks receive ParsedPacket objects. Thread-safe.
    """

    def __init__(self):
        self._callbacks: List[Callable[[ParsedPacket], None]] = []
        self._running      = False
        self._thread: Optional[threading.Thread] = None
        self._packets: List[ParsedPacket] = []
        self._lock    = threading.Lock()
        self.stats    = PacketStats()
        self.simulator = TrafficSimulator()

    # ── Callback registration ────────────────────────────────────────────────
    def add_callback(self, fn: Callable[[ParsedPacket], None]):
        self._callbacks.append(fn)

    def _dispatch(self, pp: ParsedPacket):
        with self._lock:
            self._packets.append(pp)
            if len(self._packets) > 5000:
                self._packets.pop(0)
        self.stats.update(pp)
        for cb in self._callbacks:
            try:
                cb(pp)
            except Exception as e:
                print(f"[Engine] Callback error: {e}")

    # ── Scapy live capture ───────────────────────────────────────────────────
    def start_live(self, iface: Optional[str] = None, bpf_filter: str = "",
                   packet_count: int = 0):
        """Start live capture using Scapy on the specified interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Run: pip install scapy")
        self._running = True

        def _scapy_cb(pkt):
            if not self._running:
                return
            pp = ProtocolParser.parse(pkt)
            self._dispatch(pp)

        def _capture():
            try:
                sniff(iface=iface, filter=bpf_filter,
                      prn=_scapy_cb, count=packet_count,
                      stop_filter=lambda _: not self._running,
                      store=False)
            except Exception as e:
                print(f"[Engine] Live capture error: {e}")
                print("[Engine] Falling back to simulation mode.")
                self._run_simulator()

        self._thread = threading.Thread(target=_capture, daemon=True)
        self._thread.start()

    # ── Simulation mode ──────────────────────────────────────────────────────
    def start_simulate(self, rate: float = 1.5):
        """Generate simulated packets at ~`rate` packets/second."""
        self._running = True

        def _simulate():
            while self._running:
                packets = self.simulator.generate_packet()
                for pp in packets:
                    if not self._running:
                        break
                    self._dispatch(pp)
                    time.sleep(random.uniform(0.05, 0.15))
                sleep_time = max(0.1, 1.0 / rate)
                time.sleep(random.uniform(sleep_time * 0.5, sleep_time * 1.5))

        self._thread = threading.Thread(target=_simulate, daemon=True)
        self._thread.start()

    def _run_simulator(self):
        """Internal fallback simulation."""
        while self._running:
            packets = self.simulator.generate_packet()
            for pp in packets:
                if not self._running:
                    break
                self._dispatch(pp)
                time.sleep(random.uniform(0.1, 0.5))

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    # ── PCAP import/export ───────────────────────────────────────────────────
    def load_pcap(self, filepath: str) -> List[ParsedPacket]:
        """Read a .pcap file and return parsed packets."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy required to read PCAP files.")
        pkts = rdpcap(filepath)
        result = []
        for pkt in pkts:
            pp = ProtocolParser.parse(pkt)
            result.append(pp)
            self._dispatch(pp)
        return result

    def export_json(self, filepath: str, filter_expr: str = "", **kwargs):
        """Export captured packets to JSON."""
        with self._lock:
            pkts = list(self._packets)
        if filter_expr:
            pkts = [p for p in pkts if PacketFilter.matches(p, filter_expr)]
        data = [p.to_dict() for p in pkts]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return len(data)

    def export_csv(self, filepath: str):
        """Export a summary CSV of captured packets."""
        import csv
        with self._lock:
            pkts = list(self._packets)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Time", "Protocol", "Src IP", "Dst IP",
                         "Src Port", "Dst Port", "Length", "Info"])
            for p in pkts:
                w.writerow([
                    p.packet_id, p.datetime_str, p.protocol,
                    p.ip_src or "", p.ip_dst or "",
                    p.tcp_sport or p.udp_sport or "",
                    p.tcp_dport or p.udp_dport or "",
                    p.length, p.info,
                ])
        return len(pkts)

    # ── Queries ───────────────────────────────────────────────────────────────
    def get_packets(self, since_id: int = 0, limit: int = 200,
                    filter_expr: str = "") -> List[dict]:
        with self._lock:
            pkts = [p for p in self._packets if p.packet_id > since_id]
        if filter_expr:
            pkts = [p for p in pkts if PacketFilter.matches(p, filter_expr)]
        return [p.to_dict() for p in pkts[-limit:]]

    def get_packet_by_id(self, pid: int) -> Optional[dict]:
        with self._lock:
            for p in self._packets:
                if p.packet_id == pid:
                    return p.to_dict()
        return None

    def clear(self):
        with self._lock:
            self._packets.clear()
        ParsedPacket._id_counter = 0

    @staticmethod
    def list_interfaces() -> List[str]:
        """Return available network interfaces."""
        if SCAPY_AVAILABLE:
            try:
                return get_if_list()
            except Exception:
                pass
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────────────────────────────────────

engine = PacketCaptureEngine()
