"""
agent.py -- NetWatch Real-Network Desktop Agent Bridge
=====================================================
Captures LIVE packets from your real Wi-Fi / Ethernet card using Scapy (primary)
or raw sockets (fallback), and streams them to your NetWatch dashboard.

Serves packets over BOTH:
  1. WebSocket  ws://localhost:9999   (browser connects here for live stream)
  2. HTTP POST  to /api/agent/packet  (pushes each packet to Flask dashboard)

LEGAL NOTICE:
  Packet sniffing must ONLY be performed on networks/devices you own or have
  explicit written permission to monitor. Unauthorized interception is illegal.

REQUIREMENTS:
  Windows  -> Run PowerShell / CMD as Administrator
              Install Npcap from https://npcap.com/ (needed by Scapy)
  Linux    -> sudo python3 agent.py
  macOS    -> sudo python3 agent.py

INSTALL (once):
  pip install scapy websockets

USAGE:
  python agent.py
  python agent.py --server https://code-alpha-basic-network-sniffer.vercel.app
  python agent.py --iface "Wi-Fi"
  python agent.py --bpf "tcp or udp"
  python agent.py --list-ifaces
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import argparse
import asyncio
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Dict, List, Optional, Set

# WebSocket server (optional)
try:
    import websockets
    import websockets.server
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False
    print("WARNING: 'websockets' not installed -- WebSocket mode disabled.")
    print("  Install with:  pip install websockets\n")

# Scapy (primary capture library)
try:
    from scapy.all import (
        ARP, DNS, DNSQR, DNSRR, Ether, ICMP, IP, IPv6,
        Raw, TCP, UDP, conf, get_if_list, sniff
    )
    try:
        from scapy.arch.windows import get_windows_if_list
        WINDOWS_SCAPY = True
    except ImportError:
        WINDOWS_SCAPY = False
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not installed -- falling back to raw socket mode.")
    print("  Install:  pip install scapy")
    print("  Npcap  :  https://npcap.com/\n")

# ---------------------------------------------------------------------------
# Protocol Tables  (must match packet_engine.py exactly)
# ---------------------------------------------------------------------------

PROTO_NAMES: Dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP",   22: "SSH",   23: "TELNET",
    25: "SMTP",     53: "DNS",   67: "DHCP",  68: "DHCP",
    69: "TFTP",     80: "HTTP",  110: "POP3", 123: "NTP",
    143: "IMAP",   161: "SNMP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

ICMP_TYPES: Dict[int, str] = {
    0: "Echo Reply",     3: "Destination Unreachable",
    4: "Source Quench",  5: "Redirect",
    8: "Echo Request",  11: "Time Exceeded",
    12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply",
}

TCP_FLAG_NAMES = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
TCP_FLAG_BITS  = [0x01,  0x02,  0x04,  0x08,  0x10,  0x20,  0x40,  0x80]

_pkt_lock    = threading.Lock()
_pkt_counter = 0


def _next_id() -> int:
    global _pkt_counter
    with _pkt_lock:
        _pkt_counter += 1
        return _pkt_counter


# ---------------------------------------------------------------------------
# WebSocket Broadcast State
# ---------------------------------------------------------------------------

_ws_clients: Set = set()
_ws_lock = threading.Lock()
_ws_loop: Optional[asyncio.AbstractEventLoop] = None


def _broadcast_ws(payload: str):
    if not WS_AVAILABLE or _ws_loop is None:
        return
    with _ws_lock:
        clients = set(_ws_clients)
    if not clients:
        return
    asyncio.run_coroutine_threadsafe(_async_broadcast(payload, clients), _ws_loop)


async def _async_broadcast(payload: str, clients: set):
    dead = []
    for ws in clients:
        try:
            await ws.send(payload)
        except Exception:
            dead.append(ws)
    with _ws_lock:
        for ws in dead:
            _ws_clients.discard(ws)


# ---------------------------------------------------------------------------
# Parsing Helpers
# ---------------------------------------------------------------------------

def _port_svc(port: int) -> str:
    return WELL_KNOWN_PORTS.get(port, "")


def _tcp_flags_dict(flags_int: int) -> Dict[str, bool]:
    return {n: bool(flags_int & b) for n, b in zip(TCP_FLAG_NAMES, TCP_FLAG_BITS)}


def _tcp_flags_str(flags_int: int) -> str:
    return "".join(n[0] for n, b in zip(TCP_FLAG_NAMES, TCP_FLAG_BITS) if flags_int & b)


def _color_class(proto: str) -> str:
    return f"proto-{proto.lower()}"


def _app_protocol(sport: Optional[int], dport: Optional[int]) -> Optional[str]:
    for port in (dport, sport):
        if port in WELL_KNOWN_PORTS:
            svc = WELL_KNOWN_PORTS[port]
            if svc in ("HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP",
                       "POP3", "IMAP", "NTP", "DHCP", "mDNS"):
                return svc
    return None


def _get_raw_payload_scapy(pkt) -> Optional[bytes]:
    try:
        if pkt.haslayer(Raw):
            return bytes(pkt[Raw].load)
        for layer in [TCP, UDP, ICMP, ARP, IP, IPv6]:
            if pkt.haslayer(layer):
                inner = pkt[layer].payload
                if inner:
                    return bytes(inner)
    except Exception:
        pass
    return None


def _set_payload_scapy(d: dict, pkt):
    raw = _get_raw_payload_scapy(pkt)
    if raw:
        d["payload_hex"]   = raw[:256].hex()
        d["payload_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:256])


# ---------------------------------------------------------------------------
# Scapy Packet -> JSON dict  (matches ParsedPacket.to_dict() schema exactly)
# ---------------------------------------------------------------------------

def scapy_packet_to_dict(pkt) -> Optional[dict]:
    """Parse a Scapy packet into the NetWatch frontend JSON schema."""
    if not pkt.haslayer(IP) and not pkt.haslayer(IPv6) and not pkt.haslayer(ARP):
        return None

    now    = time.time()
    pkt_id = _next_id()
    ts     = float(pkt.time) if hasattr(pkt, "time") else now
    dt_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

    d = {
        "id": pkt_id, "timestamp": ts, "time": dt_str, "datetime_str": dt_str,
        "length": len(pkt), "protocol": "UNKNOWN", "info": "",
        "color_class": "proto-unknown",
        "eth_src": None, "eth_dst": None, "eth_type": None,
        "ip_src": None, "ip_dst": None, "ip_version": None, "ip_ttl": None,
        "ip_proto": None, "ip_proto_name": None, "ip_hdr_len": None,
        "ip_checksum": None, "ip_flags": None,
        "tcp_sport": None, "tcp_dport": None, "tcp_flags": None,
        "tcp_flags_str": None, "tcp_seq": None, "tcp_ack": None,
        "tcp_window": None, "tcp_checksum": None,
        "udp_sport": None, "udp_dport": None, "udp_len": None, "udp_checksum": None,
        "icmp_type": None, "icmp_type_name": None, "icmp_code": None,
        "app_protocol": None, "app_data": None,
        "payload_hex": None, "payload_ascii": None,
    }

    # Layer 2 - Ethernet
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        d["eth_src"]  = eth.src
        d["eth_dst"]  = eth.dst
        d["eth_type"] = hex(eth.type)

    # Layer 3 - ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        d["protocol"]    = "ARP"
        d["color_class"] = "proto-arp"
        d["ip_src"]      = arp.psrc
        d["ip_dst"]      = arp.pdst
        op = "Request" if arp.op == 1 else "Reply"
        d["info"] = f"ARP {op}: Who has {arp.pdst}? Tell {arp.psrc}"
        _set_payload_scapy(d, pkt)
        return d

    # Layer 3 - IPv4
    if pkt.haslayer(IP):
        ip = pkt[IP]
        d["ip_src"]        = ip.src
        d["ip_dst"]        = ip.dst
        d["ip_version"]    = 4
        d["ip_ttl"]        = ip.ttl
        d["ip_proto"]      = ip.proto
        d["ip_proto_name"] = PROTO_NAMES.get(ip.proto, str(ip.proto))
        d["ip_hdr_len"]    = ip.ihl * 4
        d["ip_checksum"]   = hex(ip.chksum) if ip.chksum else None
        d["ip_flags"]      = str(ip.flags)
    elif pkt.haslayer(IPv6):
        ipv6 = pkt[IPv6]
        d["ip_src"]        = ipv6.src
        d["ip_dst"]        = ipv6.dst
        d["ip_version"]    = 6
        d["ip_ttl"]        = ipv6.hlim
        d["ip_proto"]      = ipv6.nh
        d["ip_proto_name"] = PROTO_NAMES.get(ipv6.nh, str(ipv6.nh))

    # Layer 4 - TCP
    if pkt.haslayer(TCP):
        tcp       = pkt[TCP]
        flags_int = int(tcp.flags)
        d["tcp_sport"]     = tcp.sport
        d["tcp_dport"]     = tcp.dport
        d["tcp_flags"]     = _tcp_flags_dict(flags_int)
        d["tcp_flags_str"] = _tcp_flags_str(flags_int)
        d["tcp_seq"]       = tcp.seq
        d["tcp_ack"]       = tcp.ack
        d["tcp_window"]    = tcp.window
        d["tcp_checksum"]  = hex(tcp.chksum) if tcp.chksum else None

        app = _app_protocol(tcp.sport, tcp.dport)
        d["protocol"]    = app or "TCP"
        d["color_class"] = _color_class(app) if app else "proto-tcp"
        if app:
            d["app_protocol"] = app

        svc_s = _port_svc(tcp.sport) or str(tcp.sport)
        svc_d = _port_svc(tcp.dport) or str(tcp.dport)
        fl    = _tcp_flags_str(flags_int) or "-"
        d["info"] = (f"TCP {d['ip_src']}:{svc_s} -> {d['ip_dst']}:{svc_d} "
                     f"[{fl}] Seq={tcp.seq} Win={tcp.window}")

        # HTTP detection from payload
        raw = _get_raw_payload_scapy(pkt)
        if raw:
            try:
                text = raw[:512].decode("utf-8", errors="replace")
                if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                    lines  = text.split("\r\n")
                    host   = next((l.split(":", 1)[1].strip() for l in lines[1:]
                                   if l.lower().startswith("host:")), d["ip_dst"])
                    d["app_protocol"] = "HTTP"
                    d["protocol"]     = "HTTP"
                    d["color_class"]  = "proto-http"
                    d["app_data"]     = {"method_path": lines[0], "host": host}
                    d["info"]         = f"HTTP {lines[0]} -> {host}"
                elif text.startswith("HTTP/"):
                    status = text.split("\r\n")[0]
                    d["app_protocol"] = "HTTP"
                    d["protocol"]     = "HTTP"
                    d["color_class"]  = "proto-http"
                    d["app_data"]     = {"response": status}
                    d["info"]         = f"HTTP {status} <- {d['ip_src']}"
            except Exception:
                pass

    # Layer 4 - UDP
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        d["udp_sport"]    = udp.sport
        d["udp_dport"]    = udp.dport
        d["udp_len"]      = udp.len
        d["udp_checksum"] = hex(udp.chksum) if udp.chksum else None

        svc_s = _port_svc(udp.sport) or str(udp.sport)
        svc_d = _port_svc(udp.dport) or str(udp.dport)

        if pkt.haslayer(DNS):
            dns     = pkt[DNS]
            queries, records = [], []
            try:
                qr = dns.qd
                for _ in range(dns.qdcount or 0):
                    queries.append({"name": qr.qname.decode("utf-8", errors="replace").rstrip("."),
                                    "type": qr.qtype})
                    qr = qr.payload
            except Exception:
                pass
            try:
                rr = dns.an
                for _ in range(dns.ancount or 0):
                    name  = rr.rrname.decode("utf-8", errors="replace").rstrip(".")
                    rdata = str(rr.rdata) if hasattr(rr, "rdata") else "?"
                    records.append({"name": name, "rdata": rdata})
                    rr = rr.payload
            except Exception:
                pass
            qname    = queries[0]["name"] if queries else "?"
            is_query = dns.qr == 0
            d["protocol"]     = "DNS"
            d["color_class"]  = "proto-dns"
            d["app_protocol"] = "DNS"
            d["app_data"]     = {"queries": queries, "records": records,
                                 "is_query": is_query, "id": dns.id}
            d["info"] = (f"DNS Query: {qname}" if is_query
                         else f"DNS Response: {qname} -> {records[0]['rdata'] if records else '?'}")
        else:
            app = _app_protocol(udp.sport, udp.dport)
            d["protocol"]    = app or "UDP"
            d["color_class"] = _color_class(app) if app else "proto-udp"
            if app:
                d["app_protocol"] = app
            d["info"] = f"UDP {d['ip_src']}:{svc_s} -> {d['ip_dst']}:{svc_d} len={udp.len}"

    # Layer 4 - ICMP
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        d["icmp_type"]      = icmp.type
        d["icmp_type_name"] = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
        d["icmp_code"]      = icmp.code
        d["protocol"]       = "ICMP"
        d["color_class"]    = "proto-icmp"
        d["info"] = f"ICMP {d['icmp_type_name']} {d['ip_src']} -> {d['ip_dst']}"

    _set_payload_scapy(d, pkt)

    if not d["info"] and d["ip_src"]:
        d["info"] = f"{d['protocol']} {d['ip_src']} -> {d['ip_dst']} len={d['length']}"

    return d


# ---------------------------------------------------------------------------
# Raw Socket Fallback Parser (Windows Administrator, no Scapy)
# ---------------------------------------------------------------------------

def raw_socket_packet_to_dict(raw_data: bytes) -> Optional[dict]:
    """Parse a raw IPv4 packet from Windows SOCK_RAW into the NetWatch JSON schema."""
    if len(raw_data) < 20:
        return None
    version_ihl = raw_data[0]
    version     = version_ihl >> 4
    if version != 4:
        return None

    ihl        = (version_ihl & 0x0F) * 4
    ip_proto   = raw_data[9]
    checksum   = struct.unpack("!H", raw_data[10:12])[0]
    ip_src     = socket.inet_ntoa(raw_data[12:16])
    ip_dst     = socket.inet_ntoa(raw_data[16:20])
    ttl        = raw_data[8]
    flags_frag = struct.unpack("!H", raw_data[6:8])[0]
    total_len  = struct.unpack("!H", raw_data[2:4])[0]

    now    = time.time()
    pkt_id = _next_id()
    dt_str = datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]

    d = {
        "id": pkt_id, "timestamp": now, "time": dt_str, "datetime_str": dt_str,
        "length": total_len, "protocol": PROTO_NAMES.get(ip_proto, f"IP({ip_proto})"),
        "info": "", "color_class": "proto-unknown",
        "eth_src": None, "eth_dst": None, "eth_type": None,
        "ip_src": ip_src, "ip_dst": ip_dst, "ip_version": version, "ip_ttl": ttl,
        "ip_proto": ip_proto, "ip_proto_name": PROTO_NAMES.get(ip_proto, str(ip_proto)),
        "ip_hdr_len": ihl, "ip_checksum": hex(checksum), "ip_flags": hex(flags_frag >> 13),
        "tcp_sport": None, "tcp_dport": None, "tcp_flags": None,
        "tcp_flags_str": None, "tcp_seq": None, "tcp_ack": None,
        "tcp_window": None, "tcp_checksum": None,
        "udp_sport": None, "udp_dport": None, "udp_len": None, "udp_checksum": None,
        "icmp_type": None, "icmp_type_name": None, "icmp_code": None,
        "app_protocol": None, "app_data": None,
        "payload_hex": None, "payload_ascii": None,
    }

    transport = raw_data[ihl:]

    if ip_proto == 6 and len(transport) >= 20:
        sport = struct.unpack("!H", transport[0:2])[0]
        dport = struct.unpack("!H", transport[2:4])[0]
        seq   = struct.unpack("!I", transport[4:8])[0]
        ack   = struct.unpack("!I", transport[8:12])[0]
        flags = transport[13]
        win   = struct.unpack("!H", transport[14:16])[0]
        chk   = struct.unpack("!H", transport[16:18])[0]
        doff  = (transport[12] >> 4) * 4
        app   = _app_protocol(sport, dport)
        d.update({"tcp_sport": sport, "tcp_dport": dport,
                  "tcp_flags": _tcp_flags_dict(flags),
                  "tcp_flags_str": _tcp_flags_str(flags),
                  "tcp_seq": seq, "tcp_ack": ack,
                  "tcp_window": win, "tcp_checksum": hex(chk),
                  "protocol": app or "TCP",
                  "color_class": _color_class(app) if app else "proto-tcp",
                  "app_protocol": app})
        svc_s = _port_svc(sport) or str(sport)
        svc_d = _port_svc(dport) or str(dport)
        d["info"] = (f"TCP {ip_src}:{svc_s} -> {ip_dst}:{svc_d} "
                     f"[{_tcp_flags_str(flags) or '-'}] Seq={seq} Win={win}")
        payload = transport[doff:]
        if payload:
            d["payload_hex"]   = payload[:256].hex()
            d["payload_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:256])

    elif ip_proto == 17 and len(transport) >= 8:
        sport  = struct.unpack("!H", transport[0:2])[0]
        dport  = struct.unpack("!H", transport[2:4])[0]
        length = struct.unpack("!H", transport[4:6])[0]
        chk    = struct.unpack("!H", transport[6:8])[0]
        app    = _app_protocol(sport, dport)
        d.update({"udp_sport": sport, "udp_dport": dport,
                  "udp_len": length, "udp_checksum": hex(chk),
                  "protocol": app or "UDP",
                  "color_class": _color_class(app) if app else "proto-udp",
                  "app_protocol": app})
        svc_s = _port_svc(sport) or str(sport)
        svc_d = _port_svc(dport) or str(dport)
        d["info"] = f"UDP {ip_src}:{svc_s} -> {ip_dst}:{svc_d} len={length}"

    elif ip_proto == 1 and len(transport) >= 4:
        icmp_type = transport[0]
        icmp_code = transport[1]
        d.update({"icmp_type": icmp_type,
                  "icmp_type_name": ICMP_TYPES.get(icmp_type, f"Type {icmp_type}"),
                  "icmp_code": icmp_code,
                  "protocol": "ICMP", "color_class": "proto-icmp"})
        d["info"] = f"ICMP {d['icmp_type_name']} {ip_src} -> {ip_dst}"

    if not d["info"]:
        d["info"] = f"{d['protocol']} {ip_src} -> {ip_dst} len={total_len}"

    return d


# ---------------------------------------------------------------------------
# HTTP POST to Flask dashboard
# ---------------------------------------------------------------------------

_http_err_count = 0


def post_to_dashboard(packet_dict: dict, post_url: str):
    global _http_err_count
    try:
        payload = json.dumps(packet_dict, default=str).encode("utf-8")
        req = urllib.request.Request(
            post_url, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
        _http_err_count = 0
    except Exception:
        _http_err_count += 1
        if _http_err_count == 1 or _http_err_count % 20 == 0:
            print(f"WARNING: Dashboard not reachable at {post_url} -- "
                  f"Is app.py running? (attempt {_http_err_count})")


# ---------------------------------------------------------------------------
# WebSocket Server
# ---------------------------------------------------------------------------

async def _ws_handler(websocket, path=None):
    with _ws_lock:
        _ws_clients.add(websocket)
    addr = websocket.remote_address
    print(f"CONNECT  Browser WebSocket connected from {addr}")
    try:
        await websocket.send(json.dumps({"type": "connected", "agent": "NetWatch Agent"}))
        await websocket.wait_closed()
    except Exception:
        pass
    finally:
        with _ws_lock:
            _ws_clients.discard(websocket)
        print(f"DISCONNECT  Browser disconnected: {addr}")


def _run_ws_server(ws_port: int):
    global _ws_loop
    _ws_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_ws_loop)

    async def _serve():
        async with websockets.server.serve(_ws_handler, "0.0.0.0", ws_port):
            print(f"WebSocket server listening on ws://localhost:{ws_port}\n")
            await asyncio.Future()

    _ws_loop.run_until_complete(_serve())


# ---------------------------------------------------------------------------
# Interface Selection
# ---------------------------------------------------------------------------

def list_interfaces() -> List[str]:
    if not SCAPY_AVAILABLE:
        return []
    good_kw = ("Wi-Fi", "WiFi", "Ethernet", "wlan", "eth", "Intel", "Realtek", "Wireless")
    bad_kw  = ("Loopback", "Bluetooth", "VMware", "VirtualBox", "Teredo",
               "6to4", "Miniport", "Pseudo", "Tunnel", "WFP", "SSTP")
    if WINDOWS_SCAPY:
        try:
            ifaces = get_windows_if_list()
            good, rest = [], []
            for iface in ifaces:
                name = iface.get("name", "") or iface.get("description", "")
                desc = iface.get("description", "")
                if any(b.lower() in desc.lower() or b.lower() in name.lower() for b in bad_kw):
                    continue
                if any(g.lower() in desc.lower() or g.lower() in name.lower() for g in good_kw):
                    good.append(name)
                else:
                    rest.append(name)
            return good + rest
        except Exception:
            pass
    try:
        return get_if_list()
    except Exception:
        return []


def pick_best_interface(preferred: Optional[str] = None) -> Optional[str]:
    ifaces = list_interfaces()
    if not ifaces:
        return None
    if preferred:
        for iface in ifaces:
            if preferred.lower() in iface.lower():
                return iface
    return ifaces[0]


# ---------------------------------------------------------------------------
# Capture Loops
# ---------------------------------------------------------------------------

def _on_scapy_packet(pkt, post_url: str, stats: dict):
    d = scapy_packet_to_dict(pkt)
    if d is None:
        return
    stats["count"] += 1
    if stats["count"] % 10 == 0:
        print(f"  [{d['time']}] #{stats['count']:>5}  {d['protocol']:<8} "
              f"{d['ip_src'] or '?'} -> {d['ip_dst'] or '?'}   {d['info'][:55]}")
    payload = json.dumps(d, default=str)
    _broadcast_ws(payload)
    post_to_dashboard(d, post_url)


def run_scapy_capture(iface: str, post_url: str, bpf: str, stats: dict):
    print(f"Scapy capturing on: {iface!r}")
    print(f"BPF filter: {bpf or 'None (all traffic)'}")
    print(f"Dashboard : {post_url}\n")
    while True:
        try:
            sniff(
                iface=iface, filter=bpf,
                prn=lambda pkt: _on_scapy_packet(pkt, post_url, stats),
                store=False,
                stop_filter=lambda _: stats.get("stop"),
            )
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Scapy error: {e} -- retrying in 3s ...")
            time.sleep(3)
        if stats.get("stop"):
            break


def run_raw_socket_capture(bind_ip: str, post_url: str, stats: dict):
    print(f"Raw Socket capturing on: {bind_ip}")
    print(f"Dashboard : {post_url}\n")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((bind_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("\nERROR: Run PowerShell / CMD as Administrator!\n")
        sys.exit(1)
    except AttributeError:
        print("\nERROR: Raw socket RCVALL mode is only supported on Windows.\n")
        sys.exit(1)
    except Exception as e:
        print(f"\nSocket error: {e}\n")
        sys.exit(1)

    try:
        while not stats.get("stop"):
            try:
                s.settimeout(1.0)
                raw_data, _ = s.recvfrom(65535)
                d = raw_socket_packet_to_dict(raw_data)
                if d is None:
                    continue
                stats["count"] += 1
                if stats["count"] % 10 == 0:
                    print(f"  [{d['time']}] #{stats['count']:>5}  {d['protocol']:<8} "
                          f"{d['ip_src'] or '?'} -> {d['ip_dst'] or '?'}   {d['info'][:55]}")
                payload = json.dumps(d, default=str)
                _broadcast_ws(payload)
                post_to_dashboard(d, post_url)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Recv error: {e}")
                time.sleep(0.2)
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetWatch Real-Network Desktop Agent Bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py
  python agent.py --server https://code-alpha-basic-network-sniffer.vercel.app
  python agent.py --iface "Wi-Fi" --bpf "tcp port 443"
  python agent.py --ws-port 9999 --no-http
  python agent.py --list-ifaces
        """
    )
    parser.add_argument("--server", default="http://127.0.0.1:5000",
                        help="NetWatch dashboard URL (default: http://127.0.0.1:5000)")
    parser.add_argument("--iface", default=None,
                        help="Network interface name (auto-detected if not set)")
    parser.add_argument("--bpf", default="",
                        help="BPF filter expression e.g. 'tcp or udp' (Scapy only)")
    parser.add_argument("--bind-ip", default=None,
                        help="Local IP for raw socket mode (auto-detected if not set)")
    parser.add_argument("--ws-port", type=int, default=9999,
                        help="WebSocket server port (default: 9999)")
    parser.add_argument("--no-ws", action="store_true",
                        help="Disable WebSocket server (HTTP POST only)")
    parser.add_argument("--no-http", action="store_true",
                        help="Disable HTTP POST to dashboard (WebSocket only)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List available network interfaces and exit")
    args = parser.parse_args()

    if args.list_ifaces:
        if SCAPY_AVAILABLE:
            ifaces = list_interfaces()
            print("\nAvailable Scapy interfaces:")
            for i, name in enumerate(ifaces, 1):
                print(f"  {i:2}. {name}")
        else:
            print("Scapy not available -- cannot list interfaces.")
        return

    print("\n" + "=" * 68)
    print("  NetWatch Real-Network Desktop Agent")
    print("=" * 68)
    print(f"  Dashboard  : {args.server}")
    print(f"  WebSocket  : ws://localhost:{args.ws_port}")
    print(f"  Capture    : {'Scapy' if SCAPY_AVAILABLE else 'Raw Socket (fallback)'}")
    print(f"  Interface  : {args.iface or 'auto-detect'}")
    print(f"  BPF Filter : {args.bpf or 'None (all traffic)'}")
    print("=" * 68)
    print("\n  LEGAL: Only sniff networks/interfaces you own or have permission to monitor.\n")

    server_url = args.server.rstrip("/")
    post_url   = f"{server_url}/api/agent/packet"
    stats      = {"count": 0, "stop": False}

    # Start WebSocket server in background thread
    if WS_AVAILABLE and not args.no_ws:
        ws_thread = threading.Thread(
            target=_run_ws_server, args=(args.ws_port,), daemon=True, name="ws-server"
        )
        ws_thread.start()
        time.sleep(0.5)
    else:
        print("WebSocket disabled -- HTTP POST only mode.\n")

    null_url = "http://127.0.0.1:0/null"

    try:
        if SCAPY_AVAILABLE:
            iface = pick_best_interface(args.iface)
            if iface is None:
                print("ERROR: No network interface found.")
                print("  Use --iface <name> or --list-ifaces to see options.")
                sys.exit(1)
            run_scapy_capture(
                iface    = iface,
                post_url = post_url if not args.no_http else null_url,
                bpf      = args.bpf,
                stats    = stats,
            )
        else:
            bind_ip = args.bind_ip
            if not bind_ip:
                try:
                    hostname = socket.gethostname()
                    for entry in socket.getaddrinfo(hostname, None, socket.AF_INET):
                        ip = entry[4][0]
                        if ip and not ip.startswith("127."):
                            bind_ip = ip
                            break
                except Exception:
                    pass
            bind_ip = bind_ip or "0.0.0.0"
            run_raw_socket_capture(
                bind_ip  = bind_ip,
                post_url = post_url if not args.no_http else null_url,
                stats    = stats,
            )
    except KeyboardInterrupt:
        stats["stop"] = True
        print(f"\nAgent stopped. Total packets streamed: {stats['count']}\n")


if __name__ == "__main__":
    main()
