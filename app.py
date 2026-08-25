"""
app.py — Flask Web Server for NetWatch Network Packet Sniffer Dashboard
=======================================================================
- REST API for packets, stats, interfaces
- Server-Sent Events (SSE) for real-time streaming
- Supports: Simulation | Live Scapy Capture | Raw Socket Capture
- Auto-detects best available capture method

Run:  python app.py          → starts in simulation mode (no admin needed)
      python app.py --live   → starts live capture on best available interface
Open: http://localhost:5000
"""

import argparse
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

from flask import (Flask, Response, jsonify, render_template,
                   request, send_file, stream_with_context)

from packet_engine import PacketCaptureEngine, PacketFilter, ParsedPacket, SCAPY_AVAILABLE

# ─────────────────────────────────────────────────────────────────────────────
# App & Engine Setup
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))
app.config["SECRET_KEY"] = "netwatch-secret-2024"

engine = PacketCaptureEngine()

# SSE subscriber queues
_sse_lock   = threading.Lock()
_sse_queues: list[queue.Queue] = []

# Capture state
_capture_state = {
    "running":   False,
    "mode":      None,   # "simulate" | "live_scapy" | "live_raw"
    "iface":     None,
    "bind_ip":   None,
    "started":   None,
    "method":    None,   # "Scapy" | "Raw Socket" | "Simulation"
}

_raw_sniffer = None  # RawSocketSniffer instance

# ─────────────────────────────────────────────────────────────────────────────
# Utility — Interface Discovery
# ─────────────────────────────────────────────────────────────────────────────

def get_interfaces() -> list[dict]:
    """
    Return a list of dicts with 'name', 'description', 'ip', 'connected'.
    Combines Windows netsh output with Scapy/raw socket info.
    """
    interfaces = []
    # Always add simulation option
    interfaces.append({
        "id":          "simulate",
        "name":        "Simulation Mode",
        "description": "Generate realistic fake packets (no admin required)",
        "ip":          None,
        "connected":   True,
        "type":        "simulate",
    })

    # Get local IPs for raw socket mode
    try:
        hostname = socket.gethostname()
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        seen_ips = set()
        for entry in addr_info:
            ip = entry[4][0]
            if ip and not ip.startswith("127.") and ip not in seen_ips:
                seen_ips.add(ip)
                interfaces.append({
                    "id":          f"raw_{ip}",
                    "name":        f"Raw Socket ({ip})",
                    "description": f"Real network capture on {ip} (Admin required)",
                    "ip":          ip,
                    "connected":   True,
                    "type":        "raw",
                })
    except Exception:
        pass

    # Add Scapy interfaces if available
    if SCAPY_AVAILABLE:
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
            # Prioritise real adapters
            good_keywords = ("Wi-Fi", "WiFi", "Ethernet", "wlan", "eth", "Intel", "Realtek")
            bad_keywords  = ("Virtual", "Loopback", "Miniport", "WFP", "Filter", "Bluetooth",
                             "Teredo", "6to4", "Tunnel", "SSTP", "PPTP", "L2TP", "IKEv2",
                             "VMware", "Pseudo")

            for iface in win_ifaces:
                name = iface.get("name", "")
                desc = iface.get("description", "")
                guid = iface.get("guid", "")
                if not name or not guid:
                    continue
                if any(b.lower() in desc.lower() or b.lower() in name.lower() for b in bad_keywords):
                    continue
                if any(g.lower() in desc.lower() or g.lower() in name.lower() for g in good_keywords):
                    npf_id = f"\\Device\\NPF_{guid.strip('{}')}"
                    interfaces.append({
                        "id":          f"scapy_{npf_id}",
                        "name":        f"Scapy: {name}",
                        "description": desc + " (Scapy — Npcap required)",
                        "ip":          iface.get("ip", ""),
                        "connected":   True,
                        "type":        "scapy",
                        "npf":         npf_id,
                    })
        except Exception:
            pass

    return interfaces


def get_best_live_iface() -> dict:
    """Return the best available live capture interface."""
    ifaces = get_interfaces()
    # Prefer Scapy Wi-Fi/Ethernet
    for i in ifaces:
        if i["type"] == "scapy" and any(x in i["name"] for x in ("Wi-Fi","WiFi","Ethernet")):
            return i
    # Fallback: raw socket
    for i in ifaces:
        if i["type"] == "raw":
            return i
    # Last resort: simulate
    return ifaces[0]

# ─────────────────────────────────────────────────────────────────────────────
# SSE Broadcast
# ─────────────────────────────────────────────────────────────────────────────

def _broadcast_packet(pp: ParsedPacket):
    data = pp.to_dict()
    msg  = f"data: {json.dumps(data, default=str)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_queues.remove(q)

engine.add_callback(_broadcast_packet)

# ─────────────────────────────────────────────────────────────────────────────
# Capture Control
# ─────────────────────────────────────────────────────────────────────────────

def _stop_all():
    global _raw_sniffer
    engine.stop()
    if _raw_sniffer:
        _raw_sniffer.stop()
        _raw_sniffer = None
    _capture_state["running"] = False


def _start_simulation(rate: float = 2.0):
    engine.start_simulate(rate=rate)
    _capture_state.update({
        "running": True, "mode": "simulate",
        "method": "Simulation", "iface": "Simulation",
        "started": datetime.now().isoformat(),
    })


def _start_raw(ip: str):
    global _raw_sniffer
    from sniffer import RawSocketSniffer
    _raw_sniffer = RawSocketSniffer()
    _raw_sniffer.add_callback(_broadcast_packet)

    def _on_raw_pkt(pp: ParsedPacket):
        with engine._lock:
            engine._packets.append(pp)
            if len(engine._packets) > 5000:
                engine._packets.pop(0)
        engine.stats.update(pp)

    _raw_sniffer.add_callback(_on_raw_pkt)
    _raw_sniffer.start(bind_ip=ip)
    _capture_state.update({
        "running": True, "mode": "live_raw",
        "method": "Raw Socket", "iface": ip, "bind_ip": ip,
        "started": datetime.now().isoformat(),
    })


def _start_scapy(npf_iface: str, bpf: str = ""):
    engine.start_live(iface=npf_iface, bpf_filter=bpf)
    _capture_state.update({
        "running": True, "mode": "live_scapy",
        "method": "Scapy", "iface": npf_iface,
        "started": datetime.now().isoformat(),
    })


# ── Auto-start based on CLI flag ─────────────────────────────────────────────
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--live", action="store_true")
_parser.add_argument("--iface", default=None)
_args, _ = _parser.parse_known_args()

if _args.live or _args.iface:
    if _args.iface:
        # User specified exact interface id
        ifaces = get_interfaces()
        match = next((i for i in ifaces if _args.iface.lower() in i["name"].lower()
                      or _args.iface == i["id"]), None)
        if match:
            if match["type"] == "raw":
                _start_raw(match["ip"])
            elif match["type"] == "scapy":
                _start_scapy(match["npf"])
            else:
                _start_simulation()
        else:
            print(f"Interface '{_args.iface}' not found, starting simulation.")
            _start_simulation()
    else:
        best = get_best_live_iface()
        if best["type"] == "raw":
            _start_raw(best["ip"])
        elif best["type"] == "scapy":
            _start_scapy(best["npf"])
        else:
            _start_simulation()
else:
    _start_simulation()

# ─────────────────────────────────────────────────────────────────────────────
# Routes — Pages
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# ─────────────────────────────────────────────────────────────────────────────
# Routes — SSE Live Stream
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/stream")
def stream():
    def event_generator():
        q: queue.Queue = queue.Queue(maxsize=500)
        with _sse_lock:
            _sse_queues.append(q)
        yield "data: {\"type\":\"connected\"}\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=15)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_queues:
                    _sse_queues.remove(q)

    return Response(
        stream_with_context(event_generator()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        }
    )

# ─────────────────────────────────────────────────────────────────────────────
# Routes — REST API
# ─────────────────────────────────────────────────────────────────────────────

from flask import send_from_directory

@app.route("/static/<path:filename>")
def custom_static(filename):
    """Ensure static CSS & JS files are always served on Vercel."""
    return send_from_directory(os.path.join(BASE_DIR, "static"), filename)


@app.route("/api/client-info")
def api_client_info():
    """
    Returns client IP address and connection details.
    Works locally or deployed on Vercel / Cloud platforms.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = request.remote_addr or "127.0.0.1"

    is_vercel = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

    return jsonify({
        "client_ip":   client_ip,
        "is_vercel":   is_vercel,
        "environment": "Vercel Cloud" if is_vercel else "Local Host",
        "user_agent":  request.headers.get("User-Agent", "Unknown"),
        "headers":     dict(request.headers),
        "timestamp":   datetime.now().isoformat(),
    })


@app.route("/api/agent/packet", methods=["POST"])
def api_agent_packet():
    """
    Endpoint for desktop agent.py to push real network packets captured
    from the user's physical Wi-Fi / Ethernet card.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No packet data"}), 400

    # Reconstruct ParsedPacket
    pp = ParsedPacket()
    for k, v in data.items():
        if hasattr(pp, k):
            setattr(pp, k, v)

    # Set mode as Real Agent
    _capture_state["mode"]   = "live_agent"
    _capture_state["method"] = "Desktop Agent (Real Network)"
    _capture_state["iface"]  = data.get("ip_src") or "Wi-Fi Agent"
    _capture_state["running"]= True

    with engine._lock:
        engine._packets.append(pp)
        if len(engine._packets) > 5000:
            engine._packets.pop(0)

    engine.stats.update(pp)
    _broadcast_packet(pp)

    return jsonify({"status": "ok", "packet_id": pp.packet_id})


@app.route("/api/packets")
def api_packets():
    since_id    = int(request.args.get("since", 0))
    limit       = min(int(request.args.get("limit", 100)), 500)
    filter_expr = request.args.get("filter", "")

    # On Vercel serverless, background threads freeze between requests.
    # Generate simulated packets on-the-fly if needed!
    is_vercel = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
    if is_vercel or len(engine._packets) < 10:
        for _ in range(5):
            new_pkts = engine.simulator.generate_packet()
            for p in new_pkts:
                engine._packets.append(p)
                engine.stats.update(p)
        if len(engine._packets) > 1000:
            engine._packets = engine._packets[-1000:]

    packets = engine.get_packets(since_id=since_id, limit=limit, filter_expr=filter_expr)
    return jsonify({"packets": packets, "count": len(packets)})


@app.route("/api/packets/<int:pid>")
def api_packet_detail(pid: int):
    pkt = engine.get_packet_by_id(pid)
    if pkt is None:
        return jsonify({"error": "Packet not found"}), 404
    return jsonify(pkt)


@app.route("/api/stats")
def api_stats():
    snap = engine.stats.snapshot()
    snap["capture"] = _capture_state
    return jsonify(snap)


@app.route("/api/interfaces")
def api_interfaces():
    ifaces = get_interfaces()
    return jsonify({
        "interfaces": ifaces,
        "scapy_available": SCAPY_AVAILABLE,
        "current": _capture_state,
    })


@app.route("/api/capture/start", methods=["POST"])
def api_start_capture():
    data    = request.get_json(silent=True) or {}
    iface_id= data.get("iface_id", "simulate")
    bpf     = data.get("bpf", "")
    rate    = float(data.get("rate", 2.0))

    _stop_all()
    time.sleep(0.3)
    engine.clear()

    # Match iface_id to discovered interface
    ifaces = get_interfaces()
    match  = next((i for i in ifaces if i["id"] == iface_id), None)

    if not match or match["type"] == "simulate":
        _start_simulation(rate=rate)
        return jsonify({"status": "started", "method": "Simulation"})

    if match["type"] == "raw":
        try:
            _start_raw(match["ip"])
            return jsonify({"status": "started", "method": "Raw Socket", "ip": match["ip"]})
        except Exception as e:
            # Fallback to simulate
            _start_simulation(rate=rate)
            return jsonify({"status": "started_fallback", "method": "Simulation",
                            "warning": str(e)}), 207

    if match["type"] == "scapy":
        try:
            _start_scapy(match["npf"], bpf)
            return jsonify({"status": "started", "method": "Scapy", "iface": match["name"]})
        except Exception as e:
            _start_simulation(rate=rate)
            return jsonify({"status": "started_fallback", "method": "Simulation",
                            "warning": str(e)}), 207

    _start_simulation(rate=rate)
    return jsonify({"status": "started", "method": "Simulation"})


@app.route("/api/capture/stop", methods=["POST"])
def api_stop_capture():
    _stop_all()
    return jsonify({"status": "stopped"})


@app.route("/api/capture/clear", methods=["POST"])
def api_clear():
    engine.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/capture/status")
def api_status():
    return jsonify(_capture_state)


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Export
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/export/json")
def export_json():
    filter_expr = request.args.get("filter", "")
    tmp = os.path.join(BASE_DIR, "capture_export.json")
    engine.export_json(tmp, filter_expr)
    return send_file(tmp, as_attachment=True,
                     download_name=f"packets_{int(time.time())}.json",
                     mimetype="application/json")


@app.route("/api/export/csv")
def export_csv():
    tmp = os.path.join(BASE_DIR, "capture_export.csv")
    engine.export_csv(tmp)
    return send_file(tmp, as_attachment=True,
                     download_name=f"packets_{int(time.time())}.csv",
                     mimetype="text/csv")


# ─────────────────────────────────────────────────────────────────────────────
# Routes — PCAP upload
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/upload/pcap", methods=["POST"])
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename.lower().endswith((".pcap", ".pcapng")):
        return jsonify({"error": "Only .pcap/.pcapng files supported"}), 400
    tmp = os.path.join(BASE_DIR, "uploaded.pcap")
    f.save(tmp)
    try:
        pkts = engine.load_pcap(tmp)
        return jsonify({"status": "loaded", "count": len(pkts)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  NetWatch Dashboard  --  http://127.0.0.1:5000")
    print(f"  Mode   : {_capture_state.get('method', 'Simulation')}")
    print(f"  Iface  : {_capture_state.get('iface', 'N/A')}")
    print("  Use --live flag to start with real network capture")
    print("  Press Ctrl+C to stop")
    print("=" * 65 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
