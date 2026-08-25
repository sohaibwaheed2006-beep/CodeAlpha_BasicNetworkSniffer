"""
agent.py — NetWatch Real-Network Desktop Agent Bridge
=====================================================
Captures REAL live packets from your local Wi-Fi / Ethernet network card
using Python's raw socket API (socket.SOCK_RAW) and streams them in real-time
to your NetWatch Web Dashboard (locally or deployed on Vercel).

Requirements:
  - Run terminal / PowerShell as Administrator
  - Python 3.9+

Usage:
  # Stream real network packets to local dashboard:
  python agent.py

  # Stream real network packets to Vercel cloud dashboard:
  python agent.py --server https://code-alpha-basic-network-sniffer.vercel.app

  # Filter specific traffic before sending:
  python agent.py --filter "proto:HTTP or proto:DNS"
"""

import argparse
import json
import os
import socket
import struct
import sys
import time
import urllib.request
import urllib.error

# Import parser helpers from sniffer.py / packet_engine.py
from sniffer import raw_packet_to_parsed
from packet_engine import PacketFilter


def get_local_ips() -> list:
    ips = []
    try:
        hostname = socket.gethostname()
        for entry in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = entry[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips or ["0.0.0.0"]


def main():
    parser = argparse.ArgumentParser(description="NetWatch Real-Network Desktop Agent")
    parser.add_argument("--server", default="http://127.0.0.1:5000",
                        help="NetWatch dashboard URL (default: http://127.0.0.1:5000)")
    parser.add_argument("--bind-ip", default=None,
                        help="Local IP to bind raw socket to (auto-detected if not set)")
    parser.add_argument("--filter", default="",
                        help="Filter expression e.g. 'proto:HTTP' or 'ip:192.168.1'")
    args = parser.parse_args()

    server_url = args.server.rstrip("/")
    post_url   = f"{server_url}/api/agent/packet"

    local_ips = get_local_ips()
    bind_ip   = args.bind_ip or local_ips[0]

    print("\n" + "=" * 65)
    print("  📡 NetWatch Real-Network Desktop Agent Bridge")
    print("=" * 65)
    print(f"  Target Dashboard : {server_url}")
    print(f"  Bound Interface  : {bind_ip}")
    print(f"  Pre-Filter       : {args.filter or 'None (All Traffic)'}")
    print("  Status           : Initializing Raw Socket Sniffer...")
    print("=" * 65 + "\n")

    # Create raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((bind_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("\n❌ ERROR: Administrator privileges required for raw socket capture.")
        print("   Right-click PowerShell or CMD → 'Run as Administrator', then run:")
        print(f"   python agent.py --server {server_url}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Socket Error: {e}")
        sys.exit(1)

    print(f"✅ CAPTURING REAL LIVE PACKETS on {bind_ip}!")
    print("   Streaming live packets to dashboard... (Press Ctrl+C to stop)\n")

    pkt_count = 0
    err_count = 0

    try:
        while True:
            try:
                s.settimeout(1.0)
                raw_data, addr = s.recvfrom(65535)
                pp = raw_packet_to_parsed(raw_data, len(raw_data))
                if pp is None:
                    continue

                if args.filter and not PacketFilter.matches(pp, args.filter):
                    continue

                pkt_count += 1
                payload = json.dumps(pp.to_dict(), default=str).encode('utf-8')

                req = urllib.request.Request(
                    post_url,
                    data=payload,
                    headers={'Content-Type': 'application/json'}
                )

                try:
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        pass
                    err_count = 0
                except urllib.error.HTTPError as e:
                    err_count += 1
                except urllib.error.URLError:
                    err_count += 1
                    if err_count % 10 == 1:
                        print(f"⚠️  Warning: Cannot reach dashboard at {server_url}. Is it running?")

                if pkt_count % 10 == 0:
                    print(f"📡 Real Packets Streamed: {pkt_count} | Last: [{pp.protocol}] {pp.info[:50]}")

            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Recv error: {e}")
                time.sleep(0.5)

    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except Exception:
            pass
        print(f"\n[Agent] Stopped. Total real packets streamed: {pkt_count}\n")


if __name__ == "__main__":
    main()
