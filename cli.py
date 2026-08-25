"""
cli.py — Rich Terminal CLI for Network Packet Sniffer
=====================================================
Usage:
    python cli.py --simulate                  # Simulated traffic mode
    python cli.py --simulate --count 20       # Capture 20 packets and stop
    python cli.py --simulate --filter proto:HTTP
    python cli.py --iface eth0                # Live capture (requires admin/npcap)
    python cli.py --pcap capture.pcap         # Analyse a .pcap file
    python cli.py --export packets.json       # Save output as JSON
    python cli.py --export packets.csv        # Save output as CSV
"""

import argparse
import os
import signal
import sys
import time
import threading
from typing import Optional

# ── Colorama for Windows terminal colours ────────────────────────────────────
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOUR = True
except ImportError:
    COLOUR = False
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _NoColor()

from packet_engine import (
    PacketCaptureEngine, PacketFilter, ParsedPacket,
    SCAPY_AVAILABLE, PROTO_NAMES, WELL_KNOWN_PORTS
)

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────────────────────────────────────

PROTO_COLORS = {
    "HTTP":    Fore.GREEN,
    "HTTPS":   Fore.CYAN,
    "DNS":     Fore.YELLOW,
    "ICMP":    Fore.MAGENTA,
    "TCP":     Fore.BLUE,
    "UDP":     Fore.WHITE,
    "ARP":     Fore.LIGHTRED_EX,
    "SSH":     Fore.LIGHTCYAN_EX,
    "DHCP":    Fore.LIGHTYELLOW_EX,
    "NTP":     Fore.LIGHTWHITE_EX,
}

def proto_color(proto: str) -> str:
    return PROTO_COLORS.get(proto, Fore.WHITE)

def hr(char: str = "─", width: int = 100) -> str:
    return char * width

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = rf"""
{Fore.CYAN}{Style.BRIGHT}
  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
         ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
         ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
         ██████╔╝███████║██║     █████╔╝ █████╗     ██║
         ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║
         ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║
         ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝
        ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
        ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
        ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
        ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
        ███████║██║ ╚████║██║██║     ██║      ███████╗██║  ██║
        ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.WHITE}        Network Packet Capture & Protocol Analysis Tool v1.0
{Fore.YELLOW}        Educational Tool — Understand how data flows through networks
{Style.RESET_ALL}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Packet Printer
# ─────────────────────────────────────────────────────────────────────────────

def print_packet_summary(pp: ParsedPacket, verbose: bool = False, detail: bool = False):
    """Print a single packet in the CLI table row format."""
    color = proto_color(pp.protocol)
    proto_badge = f"[{pp.protocol:<7}]"

    # Direction arrow
    src = pp.ip_src or pp.eth_src or "?"
    dst = pp.ip_dst or pp.eth_dst or "?"

    line = (f"{Fore.LIGHTBLACK_EX}{pp.packet_id:>5} {Style.RESET_ALL}"
            f"{Fore.LIGHTBLACK_EX}{pp.datetime_str:<14}{Style.RESET_ALL}"
            f"{color}{Style.BRIGHT}{proto_badge:<10}{Style.RESET_ALL}"
            f"{Fore.WHITE}{src:<20} → {dst:<20}{Style.RESET_ALL}"
            f"{Fore.LIGHTBLACK_EX}{pp.length:>5} B{Style.RESET_ALL}  "
            f"{Fore.WHITE}{pp.info[:55]}{Style.RESET_ALL}")
    print(line)

    if verbose:
        print_packet_detail(pp)

def print_packet_detail(pp: ParsedPacket):
    """Print full protocol-layer detail for a packet."""
    indent = "  "
    print(f"\n{Fore.CYAN}{hr('═', 80)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT} Packet #{pp.packet_id} — {pp.protocol}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{hr('─', 80)}{Style.RESET_ALL}")

    # Ethernet
    if pp.eth_src:
        print(f"{indent}{Fore.LIGHTBLUE_EX}▶ Layer 2 — Ethernet{Style.RESET_ALL}")
        print(f"{indent*2}Src MAC : {pp.eth_src}")
        print(f"{indent*2}Dst MAC : {pp.eth_dst}")
        print(f"{indent*2}EtherType: {pp.eth_type}")

    # IP
    if pp.ip_src:
        v = pp.ip_version or 4
        print(f"\n{indent}{Fore.LIGHTBLUE_EX}▶ Layer 3 — IPv{v}{Style.RESET_ALL}")
        print(f"{indent*2}Src IP    : {pp.ip_src}")
        print(f"{indent*2}Dst IP    : {pp.ip_dst}")
        if pp.ip_ttl is not None:
            print(f"{indent*2}TTL       : {pp.ip_ttl}")
        if pp.ip_hdr_len:
            print(f"{indent*2}Hdr Len   : {pp.ip_hdr_len} bytes")
        if pp.ip_proto_name:
            print(f"{indent*2}Protocol  : {pp.ip_proto_name} ({pp.ip_proto})")
        if pp.ip_checksum:
            print(f"{indent*2}Checksum  : {pp.ip_checksum}")
        if pp.ip_flags:
            print(f"{indent*2}Flags     : {pp.ip_flags}")

    # TCP
    if pp.tcp_sport is not None:
        print(f"\n{indent}{Fore.LIGHTBLUE_EX}▶ Layer 4 — TCP{Style.RESET_ALL}")
        src_svc = WELL_KNOWN_PORTS.get(pp.tcp_sport, "")
        dst_svc = WELL_KNOWN_PORTS.get(pp.tcp_dport, "")
        print(f"{indent*2}Src Port  : {pp.tcp_sport}{f' ({src_svc})' if src_svc else ''}")
        print(f"{indent*2}Dst Port  : {pp.tcp_dport}{f' ({dst_svc})' if dst_svc else ''}")
        print(f"{indent*2}Flags     : {Fore.YELLOW}{pp.tcp_flags_str}{Style.RESET_ALL}")
        print(f"{indent*2}Seq Num   : {pp.tcp_seq}")
        print(f"{indent*2}Ack Num   : {pp.tcp_ack}")
        print(f"{indent*2}Window    : {pp.tcp_window}")
        if pp.tcp_checksum:
            print(f"{indent*2}Checksum  : {pp.tcp_checksum}")

    # UDP
    if pp.udp_sport is not None:
        print(f"\n{indent}{Fore.LIGHTBLUE_EX}▶ Layer 4 — UDP{Style.RESET_ALL}")
        src_svc = WELL_KNOWN_PORTS.get(pp.udp_sport, "")
        dst_svc = WELL_KNOWN_PORTS.get(pp.udp_dport, "")
        print(f"{indent*2}Src Port  : {pp.udp_sport}{f' ({src_svc})' if src_svc else ''}")
        print(f"{indent*2}Dst Port  : {pp.udp_dport}{f' ({dst_svc})' if dst_svc else ''}")
        print(f"{indent*2}Length    : {pp.udp_len}")
        if pp.udp_checksum:
            print(f"{indent*2}Checksum  : {pp.udp_checksum}")

    # ICMP
    if pp.icmp_type is not None:
        print(f"\n{indent}{Fore.LIGHTBLUE_EX}▶ Layer 4 — ICMP{Style.RESET_ALL}")
        print(f"{indent*2}Type : {pp.icmp_type} ({pp.icmp_type_name})")
        print(f"{indent*2}Code : {pp.icmp_code}")

    # Application
    if pp.app_protocol:
        print(f"\n{indent}{Fore.LIGHTGREEN_EX}▶ Layer 7 — {pp.app_protocol}{Style.RESET_ALL}")
        if pp.app_data:
            for k, v in pp.app_data.items():
                if k not in ("raw_headers",) and v is not None:
                    if isinstance(v, list) and len(v) > 0:
                        print(f"{indent*2}{k:<14}: {v[0]}")
                    else:
                        print(f"{indent*2}{k:<14}: {v}")

    # Payload Hex Dump
    if pp.raw_payload:
        print(f"\n{indent}{Fore.LIGHTBLUE_EX}▶ Payload — Hex Dump ({len(pp.raw_payload)} bytes){Style.RESET_ALL}")
        hex_dump = ParsedPacket.format_hex_dump(pp.raw_payload)
        for row in hex_dump.split("\n"):
            print(f"{indent*2}{Fore.LIGHTBLACK_EX}{row}{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{hr('═', 80)}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Stats Printer
# ─────────────────────────────────────────────────────────────────────────────

def print_stats(engine: PacketCaptureEngine):
    snap = engine.stats.snapshot()
    print(f"\n{Fore.CYAN}{hr('═', 80)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT} 📊 Capture Statistics{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{hr('─', 80)}{Style.RESET_ALL}")
    print(f"  Total Packets  : {Fore.GREEN}{snap['total_packets']}{Style.RESET_ALL}")
    print(f"  Total Bytes    : {Fore.GREEN}{snap['total_bytes']:,}{Style.RESET_ALL}")

    print(f"\n  {Fore.YELLOW}Protocol Distribution:{Style.RESET_ALL}")
    proto_counts = sorted(snap['protocol_counts'].items(), key=lambda x: x[1], reverse=True)
    total = max(snap['total_packets'], 1)
    for proto, count in proto_counts:
        bar_len = int((count / total) * 30)
        bar = "█" * bar_len
        pct = count / total * 100
        c = proto_color(proto)
        print(f"    {c}{proto:<8}{Style.RESET_ALL}  {bar:<30}  {count:>5} ({pct:4.1f}%)")

    print(f"\n  {Fore.YELLOW}Top Source IPs:{Style.RESET_ALL}")
    for ip, cnt in snap['top_src'][:5]:
        print(f"    {Fore.WHITE}{ip:<20}{Style.RESET_ALL}  {cnt} packets")

    print(f"\n  {Fore.YELLOW}Top Destination IPs:{Style.RESET_ALL}")
    for ip, cnt in snap['top_dst'][:5]:
        print(f"    {Fore.WHITE}{ip:<20}{Style.RESET_ALL}  {cnt} packets")

    print(f"{Fore.CYAN}{hr('═', 80)}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="NetWatch — Real-Network Packet Capture & Protocol Analyser"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--simulate", action="store_true",
                      help="Generate simulated network traffic (no admin required)")
    mode.add_argument("--raw", action="store_true",
                      help="Real network capture via raw socket (requires Admin, no Npcap needed)")
    mode.add_argument("--iface", metavar="INTERFACE",
                      help="Live capture via Scapy on named interface (requires Admin + Npcap)")
    mode.add_argument("--pcap", metavar="FILE",
                      help="Read and analyse a .pcap file")
    parser.add_argument("--count",   type=int,   default=0,
                        help="Stop after N packets (0 = unlimited)")
    parser.add_argument("--filter",  type=str,   default="",
                        help="Filter expression e.g. 'proto:HTTP' or 'ip:8.8.8.8'")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full protocol details for each packet")
    parser.add_argument("--export",  metavar="FILE",
                        help="Export captured packets to .json or .csv file")
    parser.add_argument("--rate",    type=float, default=2.0,
                        help="Simulated packet rate per second (default: 2)")
    parser.add_argument("--bind-ip", metavar="IP", default=None,
                        help="Local IP to bind raw socket to (auto-detected if not set)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List available network interfaces and exit")

    args = parser.parse_args()

    # ── List interfaces ──────────────────────────────────────────────────────
    if args.list_ifaces:
        import socket as _sock
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  Available Network Interfaces")
        print(f"{'='*60}{Style.RESET_ALL}")

        # Local IPs (for raw socket)
        try:
            hostname = _sock.gethostname()
            addr_info = _sock.getaddrinfo(hostname, None, _sock.AF_INET)
            seen = set()
            for entry in addr_info:
                ip = entry[4][0]
                if ip and not ip.startswith('127.') and ip not in seen:
                    seen.add(ip)
                    print(f"  {Fore.GREEN}[RAW]{Style.RESET_ALL} {ip}  — use: python cli.py --raw --bind-ip {ip}")
        except Exception:
            pass

        # Scapy interfaces
        if SCAPY_AVAILABLE:
            ifaces = PacketCaptureEngine.list_interfaces()
            print(f"\n  {Fore.YELLOW}Scapy interfaces (requires Npcap):{Style.RESET_ALL}")
            for iface in ifaces:
                print(f"  {Fore.CYAN}[SCAPY]{Style.RESET_ALL} {iface}")
        else:
            print(f"\n  {Fore.YELLOW}Scapy not available — Npcap not installed.{Style.RESET_ALL}")

        print(f"\n  {Fore.WHITE}Simulation:{Style.RESET_ALL} python cli.py --simulate  (no admin required)")
        print()
        sys.exit(0)

    print(BANNER)

    engine = PacketCaptureEngine()
    captured_count = [0]
    stop_event = threading.Event()
    filter_expr = args.filter or ""

    # ── Packet callback ───────────────────────────────────────────────────────
    def on_packet(pp: ParsedPacket):
        if not PacketFilter.matches(pp, filter_expr):
            return
        captured_count[0] += 1
        print_packet_summary(pp, verbose=args.verbose)
        if args.count and captured_count[0] >= args.count:
            stop_event.set()

    engine.add_callback(on_packet)

    # ── Table header ──────────────────────────────────────────────────────────
    print(f"{Fore.CYAN}{hr()}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}"
          f"{'#':>5}  {'Time':<14} {'Protocol':<10} {'Src IP':<20}   {'Dst IP':<20} {'Len':>6}  Info"
          f"{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{hr()}{Style.RESET_ALL}")

    # ── Ctrl+C handler ────────────────────────────────────────────────────────
    def signal_handler(sig, frame):
        print(f"\n\n{Fore.YELLOW}Capture interrupted by user.{Style.RESET_ALL}")
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    # ── Start mode ────────────────────────────────────────────────────────────
    if args.pcap:
        print(f"\n{Fore.YELLOW}Reading PCAP file: {args.pcap}{Style.RESET_ALL}\n")
        try:
            engine.load_pcap(args.pcap)
        except Exception as e:
            print(f"{Fore.RED}Error reading PCAP: {e}{Style.RESET_ALL}")
            sys.exit(1)
        stop_event.set()

    elif args.raw:
        # ── Real-network raw socket capture ─────────────────────────────────
        from sniffer import RawSocketSniffer
        import socket as _sock

        bind_ip = args.bind_ip
        if not bind_ip:
            try:
                hostname = _sock.gethostname()
                addr_info = _sock.getaddrinfo(hostname, None, _sock.AF_INET)
                for entry in addr_info:
                    ip = entry[4][0]
                    if ip and not ip.startswith('127.'):
                        bind_ip = ip
                        break
            except Exception:
                pass
        bind_ip = bind_ip or '0.0.0.0'

        print(f"\n{Fore.GREEN}[REAL NETWORK CAPTURE]{Style.RESET_ALL}")
        print(f"  Binding to  : {Fore.CYAN}{bind_ip}{Style.RESET_ALL}")
        print(f"  Filter      : {filter_expr or 'none'}")
        print(f"  Count limit : {args.count or 'unlimited'}")
        print(f"  Method      : Raw Socket (no Npcap required)")
        print(f"  {Fore.YELLOW}NOTE: Requires Administrator / Run As Admin{Style.RESET_ALL}\n")

        raw_sniffer = RawSocketSniffer()

        def on_raw_packet(pp: ParsedPacket):
            if not PacketFilter.matches(pp, filter_expr):
                return
            with engine._lock:
                engine._packets.append(pp)
                if len(engine._packets) > 5000:
                    engine._packets.pop(0)
            engine.stats.update(pp)
            on_packet(pp)

        raw_sniffer.add_callback(on_raw_packet)
        raw_sniffer.start(bind_ip=bind_ip)
        stop_event.wait()
        raw_sniffer.stop()

    elif args.iface:
        print(f"\n{Fore.GREEN}[LIVE SCAPY CAPTURE]{Style.RESET_ALL}")
        print(f"  Interface   : {Fore.CYAN}{args.iface}{Style.RESET_ALL}")
        print(f"  Filter      : {filter_expr or 'none'}")
        print(f"  {Fore.YELLOW}NOTE: Requires Administrator + Npcap installed{Style.RESET_ALL}\n")
        engine.start_live(iface=args.iface, packet_count=args.count)
        stop_event.wait()

    else:
        # Default: simulate
        mode_name = "Simulation Mode" if args.simulate else "Simulation Mode (default)"
        print(f"\n{Fore.YELLOW}[{mode_name}]{Style.RESET_ALL} — Generating realistic traffic")
        print(f"  Filter: {filter_expr or 'none'} | Rate: {args.rate:.1f} pkt/s | Count: {args.count or 'unlimited'}\n")
        engine.start_simulate(rate=args.rate)
        stop_event.wait()

    engine.stop()
    try:
        if 'raw_sniffer' in dir() and raw_sniffer:
            raw_sniffer.stop()
    except Exception:
        pass

    # ── Summary stats ─────────────────────────────────────────────────────────
    print_stats(engine)

    # ── Export ────────────────────────────────────────────────────────────────
    if args.export:
        ext = os.path.splitext(args.export)[1].lower()
        try:
            if ext == ".csv":
                count = engine.export_csv(args.export)
            else:
                count = engine.export_json(args.export, filter_expr)
            print(f"{Fore.GREEN}✔ Exported {count} packets → {args.export}{Style.RESET_ALL}\n")
        except Exception as e:
            print(f"{Fore.RED}Export error: {e}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
