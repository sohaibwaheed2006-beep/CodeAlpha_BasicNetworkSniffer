# NetWatch — Network Packet Capture & Protocol Analyzer

> **CodeAlpha Internship Task** — Basic Network Sniffer  
> A full-featured Python network packet capture tool with a real-time Web Dashboard and CLI.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-green)
![Scapy](https://img.shields.io/badge/Scapy-2.7-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Tests](https://img.shields.io/badge/Tests-56%20passing-brightgreen)

---

## Features

- **Real Network Capture** — Live packet sniffing via Raw Sockets (no Npcap needed!) or Scapy
- **Deep Protocol Parsing** — Ethernet, IPv4, TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP, SSH, DHCP, NTP
- **Web Dashboard** — Dark glassmorphism UI with real-time SSE streaming at `http://localhost:5000`
- **Packet Inspector Modal** — Layer tree, Hex dump, Raw JSON view
- **Live Analytics** — Protocol distribution bars, throughput sparkline, top IP rankings
- **Filter Engine** — `proto:HTTP`, `ip:8.8.8.8`, `port:443`, `payload:json`, `AND`/`OR` logic
- **Protocol Guide Tab** — Educational OSI model, TCP flags, port reference
- **CLI Sniffer** — Colored terminal output with verbose mode and export
- **Export** — JSON and CSV from both CLI and Web UI
- **Simulation Mode** — Test without admin rights using realistic generated traffic
- **56 Unit Tests** — Fully verified and passing

---

## Quick Start

### Install Dependencies
```bash
pip install scapy flask colorama
```

### Run Web Dashboard (Simulation — No Admin Required)
```bash
python app.py
# Open http://localhost:5000
```

### Run with Real Network Capture (Admin Required)
```bash
# Right-click terminal → Run as Administrator
python app.py --live

# Or specify mode in the dashboard UI (Interface Selector)
```

### CLI — Simulation Mode
```bash
python cli.py --simulate
python cli.py --simulate --count 20 --verbose
python cli.py --simulate --filter "proto:HTTP or proto:DNS"
python cli.py --simulate --count 50 --export capture.json
```

### CLI — Real Network Capture (Admin Required)
```bash
# List available interfaces
python cli.py --list-ifaces

# Raw socket capture (no Npcap — just Admin)
python cli.py --raw

# Raw socket on specific IP
python cli.py --raw --bind-ip 192.168.1.10

# Scapy capture (requires Npcap)
python cli.py --iface "Wi-Fi"
```

### Run Tests
```bash
python -m unittest test_sniffer.py -v
# Ran 56 tests in ~9s   OK
```

---

## How It Works

### Capture Methods (Best → Fallback)
```
1. Raw Socket (socket.SOCK_RAW)  ← Works without Npcap, just needs Admin
2. Scapy sniff()                 ← Full promiscuous mode, needs Npcap + Admin  
3. Simulation Mode               ← No admin needed, great for learning
```

### Data Flow
```
Network Interface OR Simulator
          │
          ▼
   PacketCaptureEngine (packet_engine.py)
          │
   Parses → ParsedPacket (Ethernet/IP/TCP/UDP/ICMP/DNS/HTTP)
          │
     ┌────┴────┐
     ▼         ▼
  cli.py    app.py (Flask)
  (terminal) (Web Dashboard via SSE)
```

### Protocol Support

| Layer | Protocols |
|-------|-----------|
| Layer 2 | Ethernet, ARP |
| Layer 3 | IPv4, IPv6 |
| Layer 4 | TCP, UDP, ICMP |
| Layer 7 | HTTP, HTTPS, DNS, SSH, DHCP, NTP |

---

## Project Structure

```
CodeAlpha_BasicNetworkSniffer/
├── packet_engine.py      # Core engine: parser, simulator, filter, stats, export
├── sniffer.py            # Real-network raw socket sniffer (no Npcap required)
├── cli.py                # Terminal CLI with colored output
├── app.py                # Flask server + SSE real-time streaming
├── test_sniffer.py       # 56 automated unit tests
├── requirements.txt      # Dependencies
├── templates/
│   └── index.html        # 3-tab web dashboard
└── static/
    ├── css/style.css     # Dark glassmorphism design
    └── js/app.js         # Real-time UI logic
```

---

## Web Dashboard

Open `http://localhost:5000` after running `python app.py`.

### Tab 1 — Live Capture
- Real-time packet stream (Server-Sent Events)
- Protocol filter pills: ALL / HTTP / HTTPS / DNS / TCP / UDP / ICMP / ARP
- Smart search bar with `proto:`, `ip:`, `port:`, `payload:`, `AND`/`OR`
- Click any row to inspect full packet detail (Layers, Hex Dump, JSON)
- Interface selector to switch between Simulation / Raw Socket / Scapy

### Tab 2 — Analytics
- Total packets, bytes, protocols, and packets/second KPIs
- Protocol distribution bars
- Live throughput sparkline chart (Canvas 2D)
- Top 5 Source and Destination IPs

### Tab 3 — Protocol Guide
- Interactive OSI 7-Layer model
- Protocol deep-dives: HTTP, DNS, TCP, UDP, ICMP, ARP
- TCP flag reference table
- Well-known port lookup

---

## Filter Expression Reference

| Expression | Example | Description |
|-----------|---------|-------------|
| `proto:<name>` | `proto:HTTP` | Exact protocol match |
| `ip:<addr>` | `ip:8.8.8.8` | Source or destination IP |
| `src:<addr>` | `src:192.168.1.10` | Source IP only |
| `dst:<addr>` | `dst:8.8.8.8` | Destination IP only |
| `port:<num>` | `port:443` | Source or destination port |
| `payload:<text>` | `payload:password` | Search in ASCII payload |
| `A and B` | `proto:TCP and ip:8.8.8.8` | Logical AND |
| `A or B` | `proto:HTTP or proto:DNS` | Logical OR |

---

## Requirements

- Python 3.9+
- `scapy` — optional (for Scapy-based live capture)
- `flask` — web dashboard
- `colorama` — colored terminal output

### For Live Capture on Windows:
- Run terminal as **Administrator** (required for raw sockets)
- **Npcap** from https://npcap.com (optional — only needed for Scapy mode)

---

## Educational Purpose

NetWatch was built as a **CodeAlpha internship task** to demonstrate:
- Packet structure: Ethernet frames, IP headers, TCP segments
- Protocol stacking (OSI model layers)
- Python raw socket programming
- Network analysis techniques (filtering, hex dumps, statistics)
- Real-time web streaming with Flask SSE

---

## License

MIT License — Free for educational and personal use.
