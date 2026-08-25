"""
sniffer.py — Real-Network Packet Sniffer using Raw Sockets (No Npcap Required)
===============================================================================
Uses Python's raw socket API (socket.AF_INET, SOCK_RAW) on Windows.
This is the fallback engine when Scapy/Npcap is not available.

On Windows this requires Administrator privileges.
"""

from __future__ import annotations
import socket
import struct
import threading
import time
from typing import Callable, List, Optional

from packet_engine import ParsedPacket, PacketStats, PacketFilter, TCP_FLAGS, ICMP_TYPES, WELL_KNOWN_PORTS


def _parse_ipv4_header(data: bytes) -> Optional[dict]:
    """Parse a raw IPv4 header from bytes."""
    if len(data) < 20:
        return None
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    ihl   = (iph[0] & 0xF) * 4
    proto = iph[6]
    src   = socket.inet_ntoa(iph[8])
    dst   = socket.inet_ntoa(iph[9])
    ttl   = iph[5]
    return {
        'ihl': ihl, 'proto': proto, 'src': src, 'dst': dst,
        'ttl': ttl, 'total_len': iph[2], 'flags': (iph[4] >> 13),
        'checksum': hex(iph[7]),
    }


def _parse_tcp(data: bytes) -> Optional[dict]:
    if len(data) < 20:
        return None
    tcph = struct.unpack('!HHLLBBHHH', data[:20])
    flags_int = tcph[5]
    flags = {name: bool(flags_int & val) for name, val in TCP_FLAGS.items()}
    active = [k for k, v in flags.items() if v]
    return {
        'sport': tcph[0], 'dport': tcph[1],
        'seq': tcph[2], 'ack': tcph[3],
        'data_offset': (tcph[4] >> 4) * 4,
        'flags': flags, 'flags_str': "+".join(active) if active else "NONE",
        'window': tcph[6], 'checksum': hex(tcph[7]),
    }


def _parse_udp(data: bytes) -> Optional[dict]:
    if len(data) < 8:
        return None
    udph = struct.unpack('!HHHH', data[:8])
    return {
        'sport': udph[0], 'dport': udph[1],
        'len': udph[2], 'checksum': hex(udph[3]),
    }


def _parse_icmp(data: bytes) -> Optional[dict]:
    if len(data) < 4:
        return None
    icmph = struct.unpack('!BBH', data[:4])
    return {
        'type': icmph[0],
        'type_name': ICMP_TYPES.get(icmph[0], f"Type {icmph[0]}"),
        'code': icmph[1],
        'checksum': hex(icmph[2]),
    }


def _try_parse_http(payload: bytes) -> Optional[dict]:
    try:
        text = payload.decode('utf-8', errors='replace')
        lines = text.split('\r\n')
        if not lines:
            return None
        first = lines[0]
        result: dict = {}
        if any(first.startswith(m) for m in ('GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH')):
            parts = first.split(' ', 2)
            result['type']    = 'request'
            result['method']  = parts[0] if len(parts) > 0 else ''
            result['uri']     = parts[1] if len(parts) > 1 else ''
            result['version'] = parts[2] if len(parts) > 2 else ''
            for line in lines[1:]:
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    result[k.lower()] = v
            return result
        if first.startswith('HTTP/'):
            parts = first.split(' ', 2)
            result['type']    = 'response'
            result['version'] = parts[0] if len(parts) > 0 else ''
            result['status']  = parts[1] if len(parts) > 1 else ''
            result['reason']  = parts[2] if len(parts) > 2 else ''
            return result
    except Exception:
        pass
    return None


def raw_packet_to_parsed(raw_data: bytes, total_len: int) -> Optional[ParsedPacket]:
    """Convert raw socket bytes into a ParsedPacket."""
    pp = ParsedPacket()
    pp.length    = total_len
    pp.ip_version = 4

    ip = _parse_ipv4_header(raw_data)
    if not ip:
        return None

    pp.ip_src       = ip['src']
    pp.ip_dst       = ip['dst']
    pp.ip_ttl       = ip['ttl']
    pp.ip_proto     = ip['proto']
    pp.ip_hdr_len   = ip['ihl']
    pp.ip_checksum  = ip['checksum']

    from packet_engine import PROTO_NAMES
    pp.ip_proto_name = PROTO_NAMES.get(ip['proto'], str(ip['proto']))
    pp.eth_type      = '0x0800'

    transport_data = raw_data[ip['ihl']:]

    # ── TCP ──────────────────────────────────────────────────────────────────
    if ip['proto'] == 6:
        tcp = _parse_tcp(transport_data)
        if not tcp:
            return None
        pp.tcp_sport    = tcp['sport']
        pp.tcp_dport    = tcp['dport']
        pp.tcp_flags    = tcp['flags']
        pp.tcp_flags_str= tcp['flags_str']
        pp.tcp_seq      = tcp['seq']
        pp.tcp_ack      = tcp['ack']
        pp.tcp_window   = tcp['window']
        pp.tcp_checksum = tcp['checksum']
        payload = transport_data[tcp['data_offset']:]

        http = _try_parse_http(payload) if payload else None
        if http:
            pp.app_protocol = 'HTTP'
            pp.app_data     = http
            pp.set_payload(payload)

        dport, sport = tcp['dport'], tcp['sport']
        if http:
            pp.protocol    = 'HTTP'
            pp.color_class = 'proto-http'
            m = http.get('method','')
            u = http.get('uri','')
            s = http.get('status','')
            pp.info = f"{m} {u}" if m else f"HTTP {s}"
        elif dport == 443 or sport == 443:
            pp.protocol    = 'HTTPS'
            pp.color_class = 'proto-https'
            pp.info = f"{pp.ip_src}:{sport} → {pp.ip_dst}:{dport} [TLS]"
        elif dport == 22 or sport == 22:
            pp.protocol    = 'SSH'
            pp.color_class = 'proto-ssh'
            pp.info = f"SSH {pp.ip_src}:{sport} → {pp.ip_dst}:{dport}"
        else:
            pp.protocol    = 'TCP'
            pp.color_class = 'proto-tcp'
            svc = WELL_KNOWN_PORTS.get(dport, WELL_KNOWN_PORTS.get(sport, ''))
            s   = f" ({svc})" if svc else ''
            pp.info = f"{pp.ip_src}:{sport} → {pp.ip_dst}:{dport}{s} [{pp.tcp_flags_str}] Seq={tcp['seq']}"

        if payload and not pp.raw_payload:
            pp.set_payload(payload)

    # ── UDP ──────────────────────────────────────────────────────────────────
    elif ip['proto'] == 17:
        udp = _parse_udp(transport_data)
        if not udp:
            return None
        pp.udp_sport    = udp['sport']
        pp.udp_dport    = udp['dport']
        pp.udp_len      = udp['len']
        pp.udp_checksum = udp['checksum']
        payload = transport_data[8:]
        if payload:
            pp.set_payload(payload)

        # Detect DNS (port 53)
        if udp['dport'] == 53 or udp['sport'] == 53:
            pp.protocol    = 'DNS'
            pp.color_class = 'proto-dns'
            is_q = udp['dport'] == 53
            # Try to read query name from raw DNS
            qname = _parse_dns_qname(payload) if payload else '?'
            pp.app_protocol = 'DNS'
            pp.app_data     = {
                'is_response': not is_q,
                'queries': [{'name': qname, 'type': 1}],
                'records': [], 'questions': 1, 'answers': 0,
            }
            pp.info = f"DNS {'Query' if is_q else 'Response'}: {qname}"
        elif udp['dport'] == 67 or udp['sport'] == 68:
            pp.protocol = 'DHCP'; pp.color_class = 'proto-udp'
            pp.info = f"DHCP {'Request' if udp['dport']==67 else 'Reply'}"
        elif udp['dport'] == 123 or udp['sport'] == 123:
            pp.protocol = 'NTP'; pp.color_class = 'proto-udp'
            pp.info = 'NTP Time Sync'
        else:
            pp.protocol = 'UDP'; pp.color_class = 'proto-udp'
            svc = WELL_KNOWN_PORTS.get(udp['dport'], WELL_KNOWN_PORTS.get(udp['sport'], ''))
            s   = f" ({svc})" if svc else ''
            pp.info = f"{pp.ip_src}:{udp['sport']} → {pp.ip_dst}:{udp['dport']}{s} Len={udp['len']}"

    # ── ICMP ─────────────────────────────────────────────────────────────────
    elif ip['proto'] == 1:
        icmp = _parse_icmp(transport_data)
        if not icmp:
            return None
        pp.icmp_type      = icmp['type']
        pp.icmp_type_name = icmp['type_name']
        pp.icmp_code      = icmp['code']
        pp.protocol       = 'ICMP'
        pp.color_class    = 'proto-icmp'
        pp.info = (f"ICMP {pp.icmp_type_name} (type={pp.icmp_type}, code={pp.icmp_code})"
                   f" {pp.ip_src} → {pp.ip_dst}")
        if len(transport_data) > 8:
            pp.set_payload(transport_data[8:])

    # ── Other ─────────────────────────────────────────────────────────────────
    else:
        pp.protocol    = pp.ip_proto_name or 'RAW'
        pp.color_class = 'proto-unknown'
        pp.info        = f"{pp.ip_proto_name} {pp.ip_src} → {pp.ip_dst}"

    if not pp.protocol or pp.protocol == 'UNKNOWN':
        pp.protocol = 'RAW'; pp.color_class = 'proto-unknown'
        pp.info = f"Raw {pp.ip_src} → {pp.ip_dst}"

    return pp


def _parse_dns_qname(data: bytes) -> str:
    """Extract the first DNS query name from raw DNS bytes."""
    try:
        # DNS header is 12 bytes
        if len(data) < 13:
            return '?'
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            offset += 1
            labels.append(data[offset:offset+length].decode('ascii', errors='replace'))
            offset += length
        return '.'.join(labels) + '.' if labels else '?'
    except Exception:
        return '?'


class RawSocketSniffer:
    """
    Real-network packet sniffer using Python raw sockets.
    Works on Windows with Administrator privileges.
    Does NOT require Npcap.
    """

    def __init__(self):
        self._running   = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[ParsedPacket], None]] = []
        self.stats = PacketStats()

    def add_callback(self, fn: Callable[[ParsedPacket], None]):
        self._callbacks.append(fn)

    def _dispatch(self, pp: ParsedPacket):
        self.stats.update(pp)
        for cb in self._callbacks:
            try:
                cb(pp)
            except Exception as e:
                print(f"[RawSniffer] Callback error: {e}")

    def start(self, bind_ip: str = '0.0.0.0', filter_fn=None):
        """
        Start capturing on all interfaces (bind_ip) or a specific IP.
        filter_fn: optional function(ParsedPacket) -> bool for pre-filtering.
        """
        self._running = True

        def _capture():
            try:
                # IPPROTO_IP on Windows with AF_INET, SOCK_RAW captures all IP traffic
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((bind_ip, 0))
                # Enable IP header in the received data
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

                print(f"[RawSniffer] Started on {bind_ip} — capturing real network traffic")

                while self._running:
                    try:
                        s.settimeout(1.0)
                        raw_data, addr = s.recvfrom(65535)
                        pp = raw_packet_to_parsed(raw_data, len(raw_data))
                        if pp is None:
                            continue
                        if filter_fn and not filter_fn(pp):
                            continue
                        self._dispatch(pp)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self._running:
                            print(f"[RawSniffer] Recv error: {e}")
                        break

            except PermissionError:
                print("\n[RawSniffer] ERROR: Administrator privileges required for raw socket capture.")
                print("            Right-click your terminal and run as Administrator, then try again.")
            except OSError as e:
                print(f"[RawSniffer] Socket error: {e}")
            finally:
                try:
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    s.close()
                except Exception:
                    pass
                print("[RawSniffer] Stopped.")

        self._thread = threading.Thread(target=_capture, daemon=True, name="RawSniffer")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)

    @staticmethod
    def get_local_ips() -> List[str]:
        """Return local IPv4 addresses of connected interfaces (non-loopback)."""
        ips = []
        try:
            hostname = socket.gethostname()
            info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for entry in info:
                ip = entry[4][0]
                if ip and not ip.startswith('127.'):
                    ips.append(ip)
        except Exception:
            pass
        if not ips:
            ips = ['0.0.0.0']
        return ips
