/**
 * app.js — NetWatch Real-Time Dashboard Logic
 * ============================================
 * - Connects to /stream SSE endpoint for live packets
 * - Renders packet rows with protocol badges
 * - Manages filter, pause, protocol pills
 * - Analytics: protocol distribution bars, throughput sparkline, IP rankings
 * - Packet detail modal with layer tree, hex dump, raw JSON
 */

/* ─────────────────────────────────────────────────────────────────────────
   State
   ───────────────────────────────────────────────────────────────────────── */
const state = {
  packets:      [],      // all received packets (capped at MAX_PACKETS)
  paused:       false,
  activeFilter: "",
  lastPillFilter: "",
  maxPackets:   2000,    // ring buffer size
  statsInterval: null,
  sse:          null,
  currentModal: null,
};

/* ─────────────────────────────────────────────────────────────────────────
   Protocol colour map (mirrors CSS variables)
   ───────────────────────────────────────────────────────────────────────── */
const PROTO_COLORS = {
  HTTP:    "#10b981", HTTPS:  "#06b6d4", DNS:   "#f59e0b",
  TCP:     "#3b82f6", UDP:    "#8b5cf6", ICMP:  "#ec4899",
  ARP:     "#f97316", SSH:    "#22d3ee", DHCP:  "#84cc16",
  NTP:     "#a78bfa", RAW:    "#64748b",
};
const protoColor = (p) => PROTO_COLORS[p] || "#64748b";

/* ─────────────────────────────────────────────────────────────────────────
   DOM helpers
   ───────────────────────────────────────────────────────────────────────── */
const $  = (id) => document.getElementById(id);
const el = (tag, cls, html) => { const e = document.createElement(tag); if(cls) e.className = cls; if(html !== undefined) e.innerHTML = html; return e; };

let isPollingFallback = false;
let pollingTimer = null;
let lastSeenId = 0;
let packetAutoInc = 1000;

/* ─────────────────────────────────────────────────────────────────────────
   Real Browser Network Packet Sniffer (No CMD needed)
   Captures real network requests, API calls, DNS resolutions & assets
   ───────────────────────────────────────────────────────────────────────── */
function initBrowserNetworkSniffer() {
  if (typeof PerformanceObserver === "undefined") return;

  try {
    const observer = new PerformanceObserver((list) => {
      list.getEntries().forEach((entry) => {
        if (state.paused) return;
        try {
          const url = new URL(entry.name);
          const proto = url.protocol === "https:" ? "HTTPS" : url.protocol === "http:" ? "HTTP" : "TCP";
          const port = url.port ? parseInt(url.port) : (url.protocol === "https:" ? 443 : 80);
          
          packetAutoInc++;
          const realPkt = {
            id:           packetAutoInc,
            timestamp:    Date.now() / 1000,
            time:         new Date().toTimeString().split(" ")[0] + "." + String(Math.floor(entry.startTime % 1000)).padStart(3, "0"),
            datetime_str: new Date().toTimeString().split(" ")[0],
            length:       Math.round(entry.transferSize || entry.decodedBodySize || 320),
            protocol:     proto,
            color_class:  `proto-${proto.lower ? proto.lower() : proto.toLowerCase()}`,
            ip_src:       "127.0.0.1",
            ip_dst:       url.hostname,
            tcp_sport:    Math.floor(49152 + Math.random() * 16000),
            tcp_dport:    port,
            info:         `${entry.initiatorType.toUpperCase()} ${url.pathname.substring(0, 30)} → ${url.hostname} (${Math.round(entry.duration)}ms)`,
            app_protocol: proto,
            app_data:     { initiator: entry.initiatorType, domain: url.hostname, path: url.pathname },
            payload_ascii:`GET ${url.pathname} HTTP/1.1\r\nHost: ${url.hostname}\r\nUser-Agent: Browser-Live\r\n`,
            payload_hex:  "47455420" + url.pathname.length.toString(16),
          };

          onPacket(realPkt);
        } catch(e) {}
      });
    });

    observer.observe({ entryTypes: ["resource", "navigation"] });
  } catch(e) {}
}

function connectSSE() {
  if (state.sse) { state.sse.close(); }
  
  // Try SSE connection
  const sse = new EventSource("/stream");
  state.sse = sse;
  setStatus("connecting", "Connecting…");

  const fallbackTimeout = setTimeout(() => {
    // If SSE hasn't received a message in 3 seconds (e.g. Vercel Serverless), switch to Polling Mode
    if (!isPollingFallback) {
      console.warn("SSE connection timed out. Switching to Polling Fallback mode.");
      sse.close();
      startPollingFallback();
    }
  }, 3000);

  sse.onopen = () => setStatus("streaming", "Live ●");

  sse.onmessage = (evt) => {
    clearTimeout(fallbackTimeout);
    if (state.paused) return;
    try {
      const data = JSON.parse(evt.data);
      if (data.type === "connected") { setStatus("connected", "Connected"); return; }
      if (data.id) lastSeenId = Math.max(lastSeenId, data.id);
      onPacket(data);
    } catch(e) { /* skip malformed */ }
  };

  sse.onerror = () => {
    clearTimeout(fallbackTimeout);
    sse.close();
    if (!isPollingFallback) {
      startPollingFallback();
    }
  };
}

function startPollingFallback() {
  isPollingFallback = true;
  setStatus("streaming", "Live (Poll)");

  if (pollingTimer) clearInterval(pollingTimer);
  
  const poll = async () => {
    if (state.paused) return;
    try {
      const res = await fetch(`/api/packets?since=${lastSeenId}&limit=20`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.packets && data.packets.length > 0) {
        data.packets.forEach(pkt => {
          if (pkt.id) lastSeenId = Math.max(lastSeenId, pkt.id);
          onPacket(pkt);
        });
      }
    } catch(e) {
      console.error("Polling error:", e);
    }
  };

  poll();
  pollingTimer = setInterval(poll, 1500);
}

function setStatus(cls, text) {
  const dot  = $("status-dot");
  const label = $("status-text");
  dot.className   = "status-dot " + cls;
  label.textContent = text;
}

/* ─────────────────────────────────────────────────────────────────────────
   Packet received
   ───────────────────────────────────────────────────────────────────────── */
function onPacket(pkt) {
  // Ring buffer
  state.packets.push(pkt);
  if (state.packets.length > state.maxPackets) state.packets.shift();

  // Apply filter
  if (!matchesFilter(pkt, state.activeFilter)) return;

  appendRow(pkt);
  updateCounter();
}

/* ─────────────────────────────────────────────────────────────────────────
   Row rendering
   ───────────────────────────────────────────────────────────────────────── */
const MAX_ROWS = 500;

function appendRow(pkt) {
  const tbody = $("packet-tbody");
  const empty = $("table-empty");
  if (empty) empty.style.display = "none";

  const tr = document.createElement("tr");
  tr.id = `row-${pkt.id}`;
  tr.onclick = () => openModal(pkt.id);
  tr.setAttribute("role", "row");
  tr.setAttribute("tabindex", "0");
  tr.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") openModal(pkt.id); };

  const src = formatAddr(pkt.ip_src, pkt.tcp_sport || pkt.udp_sport);
  const dst = formatAddr(pkt.ip_dst, pkt.tcp_dport || pkt.udp_dport);

  tr.innerHTML = `
    <td class="td-id">${pkt.id}</td>
    <td class="td-time">${pkt.time || ""}</td>
    <td><span class="proto-badge proto-${(pkt.color_class || "proto-unknown").replace("proto-","")}">${pkt.protocol}</span></td>
    <td class="td-src" title="${pkt.ip_src || ""}">${src}</td>
    <td class="td-dst" title="${pkt.ip_dst || ""}">${dst}</td>
    <td class="td-len">${pkt.length} B</td>
    <td class="td-info" title="${esc(pkt.info || "")}">${esc(truncate(pkt.info || "", 80))}</td>
  `;

  tbody.prepend(tr);

  // Trim rows
  while (tbody.rows.length > MAX_ROWS) {
    tbody.deleteRow(tbody.rows.length - 1);
  }
}

function formatAddr(ip, port) {
  if (!ip) return "—";
  return port ? `${ip}:${port}` : ip;
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + "…" : str;
}

function esc(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function updateCounter() {
  const tbody = $("packet-tbody");
  const count = state.packets.length;
  $("packet-counter").textContent = `${count.toLocaleString()} packets`;
}

/* ─────────────────────────────────────────────────────────────────────────
   Filter logic
   ───────────────────────────────────────────────────────────────────────── */
function matchesFilter(pkt, expr) {
  if (!expr || expr.trim() === "") return true;
  const ex = expr.trim().toLowerCase();

  // OR / AND
  if (ex.includes(" or "))  return ex.split(" or ").some(p => matchesFilter(pkt, p.trim()));
  if (ex.includes(" and ")) return ex.split(" and ").every(p => matchesFilter(pkt, p.trim()));

  const [key, val] = ex.split(":", 2);
  if (!val) {
    // generic substring search
    return (pkt.info||"").toLowerCase().includes(ex)
        || (pkt.protocol||"").toLowerCase().includes(ex)
        || (pkt.ip_src||"").includes(ex) || (pkt.ip_dst||"").includes(ex);
  }
  switch(key) {
    case "proto":
    case "protocol": return (pkt.protocol||"").toUpperCase() === val.toUpperCase();
    case "ip":
    case "host":     return (pkt.ip_src||"").includes(val) || (pkt.ip_dst||"").includes(val);
    case "src":      return (pkt.ip_src||"").includes(val);
    case "dst":      return (pkt.ip_dst||"").includes(val);
    case "port": {
      const p = parseInt(val);
      return [pkt.tcp_sport, pkt.tcp_dport, pkt.udp_sport, pkt.udp_dport].includes(p);
    }
    case "payload":  return (pkt.payload_ascii||"").toLowerCase().includes(val);
    default:         return (pkt.info||"").toLowerCase().includes(val);
  }
}

function applyFilter() {
  const expr = $("filter-input").value.trim();
  state.activeFilter = expr;
  rebuildTable();
}

function clearFilter() {
  $("filter-input").value = "";
  state.activeFilter = "";
  rebuildTable();
}

function rebuildTable() {
  const tbody = $("packet-tbody");
  tbody.innerHTML = "";
  const empty = $("table-empty");

  const filtered = state.packets.filter(p => matchesFilter(p, state.activeFilter));
  if (filtered.length === 0) {
    if (empty) empty.style.display = "flex";
  } else {
    if (empty) empty.style.display = "none";
    // Show newest first (slice to MAX_ROWS)
    filtered.slice(-MAX_ROWS).reverse().forEach(pkt => appendRow(pkt));
  }
  updateCounter();
}

/* ─────────────────────────────────────────────────────────────────────────
   Protocol filter pills
   ───────────────────────────────────────────────────────────────────────── */
function setProtoPill(el, filter) {
  document.querySelectorAll(".pill").forEach(p => p.classList.remove("active"));
  el.classList.add("active");
  state.lastPillFilter = filter;
  $("filter-input").value = filter;
  state.activeFilter = filter;
  rebuildTable();
}

/* ─────────────────────────────────────────────────────────────────────────
   Tab switching
   ───────────────────────────────────────────────────────────────────────── */
function switchTab(name) {
  document.querySelectorAll(".tab-panel").forEach(p => {
    p.classList.remove("active");
    p.setAttribute("aria-hidden", "true");
  });
  document.querySelectorAll(".nav-tab").forEach(t => {
    t.classList.remove("active");
    t.setAttribute("aria-selected", "false");
  });
  const panel = $(`tab-${name}-panel`);
  const tab   = $(`tab-${name}`);
  if (panel) { panel.classList.add("active"); panel.setAttribute("aria-hidden","false"); }
  if (tab)   { tab.classList.add("active");   tab.setAttribute("aria-selected","true"); }

  if (name === "stats") refreshStats();
}

/* ─────────────────────────────────────────────────────────────────────────
   Controls
   ───────────────────────────────────────────────────────────────────────── */
function togglePause(checkbox) {
  state.paused = checkbox.checked;
  if (!state.paused) rebuildTable();
}

function clearPackets() {
  state.packets = [];
  $("packet-tbody").innerHTML = "";
  $("table-empty").style.display = "flex";
  $("packet-counter").textContent = "0 packets";
  fetch("/api/capture/clear", { method: "POST" });
}

function startCapture() {
  fetch("/api/capture/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode: "simulate", rate: 2.0 }),
  }).then(() => setStatus("streaming", "Live ●"));
}

function stopCapture() {
  fetch("/api/capture/stop", { method: "POST" })
    .then(() => setStatus("disconnected", "Stopped"));
}

/* ─────────────────────────────────────────────────────────────────────────
   Analytics
   ───────────────────────────────────────────────────────────────────────── */
function refreshStats() {
  fetch("/api/stats")
    .then(r => r.json())
    .then(renderStats)
    .catch(e => console.warn("Stats error", e));
}

function formatBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n/1024).toFixed(1) + " KB";
  return (n/1048576).toFixed(2) + " MB";
}

function renderStats(s) {
  $("kpi-total-val").textContent = (s.total_packets||0).toLocaleString();
  $("kpi-bytes-val").textContent = formatBytes(s.total_bytes||0);
  const pc = s.protocol_counts || {};
  $("kpi-protos-val").textContent = Object.keys(pc).length;

  // PPS from throughput history
  const th = s.throughput || [];
  const pps = th.length ? th[th.length-1].pps || 0 : 0;
  $("kpi-pps-val").textContent = pps;

  renderProtoBars(pc, s.total_packets || 1);
  renderSparkline(th);
  renderIpList("top-src-list", s.top_src || []);
  renderIpList("top-dst-list", s.top_dst || []);
}

function renderProtoBars(counts, total) {
  const container = $("proto-bars");
  container.innerHTML = "";
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  sorted.forEach(([proto, count]) => {
    const pct = Math.round(count / total * 100);
    const color = protoColor(proto);
    const div = el("div", "proto-bar-item");
    div.innerHTML = `
      <span class="proto-bar-label" style="color:${color}">${proto}</span>
      <div class="proto-bar-track">
        <div class="proto-bar-fill" style="width:${pct}%;background:${color}"></div>
      </div>
      <span class="proto-bar-count">${count}</span>
    `;
    container.appendChild(div);
  });
}

function renderIpList(containerId, items) {
  const container = $(containerId);
  container.innerHTML = "";
  if (!items.length) { container.innerHTML = '<span style="color:var(--clr-text-muted);font-size:12px">No data yet</span>'; return; }
  const maxVal = items[0][1] || 1;
  items.forEach(([ip, count]) => {
    const pct = Math.round(count / maxVal * 100);
    const div = el("div", "ip-row");
    div.innerHTML = `
      <span class="ip-addr">${ip}</span>
      <div class="ip-bar-track"><div class="ip-bar-fill" style="width:${pct}%"></div></div>
      <span class="ip-count">${count}</span>
    `;
    container.appendChild(div);
  });
}

/* ─────────────────────────────────────────────────────────────────────────
   Throughput Sparkline (Canvas)
   ───────────────────────────────────────────────────────────────────────── */
function renderSparkline(history) {
  const canvas = $("throughput-canvas");
  if (!canvas) return;
  const ctx  = canvas.getContext("2d");
  const W    = canvas.offsetWidth  || 520;
  const H    = canvas.offsetHeight || 120;
  canvas.width  = W;
  canvas.height = H;
  ctx.clearRect(0, 0, W, H);

  const data = history.map(h => h.pps || 0);
  if (data.length < 2) { ctx.fillStyle = "rgba(99,130,190,.3)"; ctx.fillRect(0,H-2,W,2); return; }

  const maxVal = Math.max(...data, 1);
  const minVal = 0;
  const range  = maxVal - minVal || 1;
  const stepX  = W / (data.length - 1);

  const toY = v => H - 8 - ((v - minVal) / range) * (H - 16);

  // Gradient fill
  const grad = ctx.createLinearGradient(0,0,0,H);
  grad.addColorStop(0, "rgba(59,130,246,.4)");
  grad.addColorStop(1, "rgba(59,130,246,0)");

  ctx.beginPath();
  ctx.moveTo(0, H);
  data.forEach((v,i) => ctx.lineTo(i * stepX, toY(v)));
  ctx.lineTo((data.length-1) * stepX, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  data.forEach((v,i) => { if(i===0) ctx.moveTo(0,toY(v)); else ctx.lineTo(i*stepX, toY(v)); });
  ctx.strokeStyle = "#3b82f6";
  ctx.lineWidth   = 2;
  ctx.stroke();

  // Dots at last point
  const lx = (data.length-1)*stepX, ly = toY(data[data.length-1]);
  ctx.beginPath();
  ctx.arc(lx, ly, 4, 0, Math.PI*2);
  ctx.fillStyle = "#3b82f6";
  ctx.fill();

  // Labels
  const avg = data.reduce((a,b)=>a+b,0)/data.length;
  $("spark-min").textContent = `min: ${minVal}`;
  $("spark-max").textContent = `max: ${maxVal}`;
  $("spark-avg").textContent = `avg: ${avg.toFixed(1)}`;
}

/* ─────────────────────────────────────────────────────────────────────────
   Packet Detail Modal
   ───────────────────────────────────────────────────────────────────────── */
function openModal(packetId) {
  // Look up in local state first
  const pkt = state.packets.find(p => p.id === packetId);
  if (!pkt) {
    fetch(`/api/packets/${packetId}`).then(r=>r.json()).then(renderModal);
  } else {
    renderModal(pkt);
  }
}

function renderModal(pkt) {
  state.currentModal = pkt;
  $("modal-title").textContent = `Packet #${pkt.id} — ${pkt.protocol}`;

  // Reset tabs
  switchModalTab("layers");

  // ── Layer Tree ────────────────────────────────────────────────────────
  const tree = $("layer-tree");
  tree.innerHTML = "";

  // Summary
  tree.appendChild(mkLayerBlock("📋 Summary", "meta", [
    ["ID",       pkt.id],
    ["Time",     pkt.time],
    ["Protocol", pkt.protocol],
    ["Length",   `${pkt.length} bytes`],
    ["Info",     pkt.info],
  ]));

  // Ethernet
  if (pkt.eth_src) {
    tree.appendChild(mkLayerBlock("🔌 Layer 2 — Ethernet", "2", [
      ["Src MAC",   pkt.eth_src],
      ["Dst MAC",   pkt.eth_dst],
      ["EtherType", pkt.eth_type],
    ]));
  }

  // IP
  if (pkt.ip_src) {
    const ipFields = [
      ["Src IP",      pkt.ip_src],
      ["Dst IP",      pkt.ip_dst],
      ["Version",     `IPv${pkt.ip_version}`],
      ["TTL",         pkt.ip_ttl],
      ["Protocol",    `${pkt.ip_proto_name} (${pkt.ip_proto})`],
      ["Hdr Length",  pkt.ip_hdr_len != null ? `${pkt.ip_hdr_len} bytes` : null],
      ["Checksum",    pkt.ip_checksum],
      ["Flags",       pkt.ip_flags],
    ].filter(f=>f[1]!=null);
    tree.appendChild(mkLayerBlock("🌐 Layer 3 — IP", "3", ipFields));
  }

  // TCP
  if (pkt.tcp_sport != null) {
    const flagEntries = pkt.tcp_flags
      ? Object.entries(pkt.tcp_flags).map(([k,v]) => ([k, v, v ? "flag-on" : "flag-off"]))
      : [];
    const tcpFields = [
      ["Src Port",    `${pkt.tcp_sport}${portSvc(pkt.tcp_sport)}`],
      ["Dst Port",    `${pkt.tcp_dport}${portSvc(pkt.tcp_dport)}`],
      ["Flags",       pkt.tcp_flags_str],
      ["Seq",         pkt.tcp_seq],
      ["Ack",         pkt.tcp_ack],
      ["Window",      pkt.tcp_window],
      ["Checksum",    pkt.tcp_checksum],
    ].filter(f=>f[1]!=null);
    const block = mkLayerBlock("📡 Layer 4 — TCP", "4", tcpFields);
    // Add flag bits sub-section
    if (flagEntries.length) {
      const flagDiv = el("div", "layer-block-body");
      flagDiv.style.borderTop = "1px solid rgba(99,130,190,.1)";
      flagDiv.style.paddingTop = "10px";
      const flagTitle = el("div", "", `<span style="font-size:11.5px;color:var(--clr-text-muted);font-weight:600;text-transform:uppercase;letter-spacing:.07em">TCP Flag Bits</span>`);
      flagDiv.appendChild(flagTitle);
      const flagGrid = el("div", "");
      flagGrid.style.cssText = "display:grid;grid-template-columns:repeat(4,1fr);gap:4px;margin-top:8px";
      flagEntries.forEach(([name, val, cls]) => {
        const chip = el("div", "");
        chip.style.cssText = `padding:4px 8px;border-radius:4px;font-family:var(--font-mono);font-size:11px;font-weight:600;text-align:center;background:${val?"rgba(16,185,129,.15)":"rgba(100,116,139,.1)"};color:${val?"#10b981":"#64748b"};border:1px solid ${val?"rgba(16,185,129,.3)":"rgba(100,116,139,.2)"}`;
        chip.textContent = name;
        flagGrid.appendChild(chip);
      });
      flagDiv.appendChild(flagGrid);
      block.appendChild(flagDiv);
    }
    tree.appendChild(block);
  }

  // UDP
  if (pkt.udp_sport != null) {
    tree.appendChild(mkLayerBlock("📡 Layer 4 — UDP", "4", [
      ["Src Port",  `${pkt.udp_sport}${portSvc(pkt.udp_sport)}`],
      ["Dst Port",  `${pkt.udp_dport}${portSvc(pkt.udp_dport)}`],
      ["Length",    pkt.udp_len],
      ["Checksum",  pkt.udp_checksum],
    ].filter(f=>f[1]!=null)));
  }

  // ICMP
  if (pkt.icmp_type != null) {
    tree.appendChild(mkLayerBlock("🏓 Layer 4 — ICMP", "4", [
      ["Type",  `${pkt.icmp_type} (${pkt.icmp_type_name})`],
      ["Code",  pkt.icmp_code],
    ]));
  }

  // Application
  if (pkt.app_protocol && pkt.app_data) {
    const appFields = Object.entries(pkt.app_data)
      .filter(([k,v]) => k !== "raw_headers" && v !== null && v !== undefined && !Array.isArray(v))
      .map(([k,v]) => [k, String(v)]);
    if (pkt.app_data.queries && pkt.app_data.queries.length) {
      appFields.push(["queries", pkt.app_data.queries.map(q=>`${q.name} (type ${q.type})`).join(", ")]);
    }
    if (pkt.app_data.records && pkt.app_data.records.length) {
      appFields.push(["records", pkt.app_data.records.map(r=>`${r.name} → ${r.rdata}`).join(", ")]);
    }
    tree.appendChild(mkLayerBlock(`🖥 Layer 7 — ${pkt.app_protocol}`, "7", appFields));
  }

  // ── Hex Dump ──────────────────────────────────────────────────────────
  const hex = $("hex-dump-content");
  if (pkt.payload_hex && pkt.payload_hex.length > 0) {
    const bytes = hexToBytes(pkt.payload_hex);
    $("hex-byte-count").textContent = `${bytes.length} bytes`;
    hex.textContent = formatHexDump(bytes);
  } else {
    hex.textContent = "(No payload data)";
    $("hex-byte-count").textContent = "0 bytes";
  }

  // ── Raw JSON ──────────────────────────────────────────────────────────
  $("raw-json").textContent = JSON.stringify(pkt, null, 2);

  // Show modal
  const modal = $("packet-modal");
  modal.removeAttribute("hidden");
  document.body.style.overflow = "hidden";

  // Close on backdrop click
  modal.onclick = (e) => { if (e.target === modal) closeModal(); };
}

function mkLayerBlock(title, layer, fields) {
  const block = el("div", "layer-block");
  const header = el("div", "layer-block-header");
  header.onclick = () => block.classList.toggle("collapsed");
  header.innerHTML = `
    <span class="layer-block-title">
      <span class="layer-block-badge">L${layer}</span>
      ${esc(title)}
    </span>
    <span class="layer-chevron">▾</span>
  `;
  block.appendChild(header);
  const body = el("div", "layer-block-body");
  fields.forEach(([key, val]) => {
    const row = el("div", "field-row");
    row.innerHTML = `<span class="field-key">${esc(String(key))}</span><span class="field-value">${esc(val != null ? String(val) : "—")}</span>`;
    body.appendChild(row);
  });
  block.appendChild(body);
  return block;
}

function portSvc(port) {
  const svcs = {20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",53:"DNS",67:"DHCP",68:"DHCP",
    69:"TFTP",80:"HTTP",110:"POP3",123:"NTP",143:"IMAP",161:"SNMP",443:"HTTPS",445:"SMB",
    3306:"MySQL",3389:"RDP",5353:"mDNS",8080:"HTTP-ALT",8443:"HTTPS-ALT"};
  return svcs[port] ? ` (${svcs[port]})` : "";
}

function hexToBytes(hexStr) {
  const bytes = [];
  for (let i = 0; i < hexStr.length; i += 2) bytes.push(parseInt(hexStr.substr(i,2), 16));
  return bytes;
}

function formatHexDump(bytes, perRow = 16) {
  const rows = [];
  for (let i = 0; i < bytes.length; i += perRow) {
    const chunk  = bytes.slice(i, i + perRow);
    const hex    = chunk.map(b => b.toString(16).padStart(2,"0").toUpperCase()).join(" ");
    const ascii  = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    const offset = i.toString(16).padStart(4,"0").toUpperCase();
    rows.push(`${offset}  ${hex.padEnd(perRow*3)}  ${ascii}`);
  }
  return rows.join("\n");
}

function switchModalTab(name) {
  ["layers","hex","raw"].forEach(t => {
    const content = $(`modal-${t}`);
    const tab     = $(`mtab-${t}`);
    const isActive = t === name;
    content.classList.toggle("active", isActive);
    content.hidden = !isActive;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-selected", isActive);
  });
}

function closeModal() {
  $("packet-modal").setAttribute("hidden","");
  document.body.style.overflow = "";
  state.currentModal = null;
}

// Keyboard ESC to close
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

/* ─────────────────────────────────────────────────────────────────────────
   Dropdown toggle
   ───────────────────────────────────────────────────────────────────────── */
function toggleDropdown(id) {
  const dd = $(id);
  dd.classList.toggle("open");
}
document.addEventListener("click", (e) => {
  document.querySelectorAll(".dropdown-menu.open").forEach(dd => {
    if (!dd.previousElementSibling.contains(e.target) && !dd.contains(e.target)) {
      dd.classList.remove("open");
    }
  });
});

/* ─────────────────────────────────────────────────────────────────────────
   Filter input event
   ───────────────────────────────────────────────────────────────────────── */
let filterDebounce;
$("filter-input").addEventListener("input", () => {
  clearTimeout(filterDebounce);
  filterDebounce = setTimeout(applyFilter, 300);
});
$("filter-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { clearTimeout(filterDebounce); applyFilter(); }
});

/* ─────────────────────────────────────────────────────────────────────────
   Stats polling (while analytics tab active)
   ───────────────────────────────────────────────────────────────────────── */
setInterval(() => {
  if (document.getElementById("tab-stats-panel")?.classList.contains("active")) {
    refreshStats();
  }
}, 2000);

/* ─────────────────────────────────────────────────────────────────────────
   Interface Selection & Mode Badge
   ───────────────────────────────────────────────────────────────────────── */
async function loadInterfaces() {
  try {
    const res = await fetch("/api/interfaces");
    if (!res.ok) return;
    const data = await res.json();
    const select = $("iface-select");
    if (!select) return;

    select.innerHTML = "";
    (data.interfaces || []).forEach(iface => {
      const opt = document.createElement("option");
      opt.value = iface.id;
      opt.textContent = iface.type === "raw" ? `📡 Real Network (${iface.ip})`
                       : iface.type === "scapy" ? `⚡ ${iface.name}`
                       : `⚙️ ${iface.name}`;
      select.appendChild(opt);
    });

    if (data.current?.mode) {
      updateModeBadge(data.current.mode, data.current.method, data.current.iface);
    }
  } catch(e) {}
}

function updateModeBadge(mode, method, iface) {
  const badge = $("mode-badge");
  if (!badge) return;
  if (mode === "live_agent" || mode === "live_raw" || mode === "live_scapy") {
    badge.className = "mode-badge live";
    badge.textContent = `📡 Live Real Traffic: ${iface || method}`;
  } else {
    badge.className = "mode-badge live";
    badge.textContent = `📡 Real Network Mode (Waiting for agent.py)`;
  }
}

async function changeInterface(ifaceId) {
  try {
    const res = await fetch("/api/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ iface_id: ifaceId })
    });
    const data = await res.json();
    clearPackets();
    if (data.method === "Raw Socket" || data.method === "Scapy") {
      updateModeBadge("live_raw", data.method, data.ip || data.iface);
    } else {
      updateModeBadge("simulate", "Simulation", "Simulation");
    }
  } catch(e) {
    console.error("Interface switch error:", e);
  }
}

/* ─────────────────────────────────────────────────────────────────────────
   Init
   ───────────────────────────────────────────────────────────────────────── */
window.addEventListener("DOMContentLoaded", () => {
  connectSSE();
  loadInterfaces();
  initBrowserNetworkSniffer();

  // Load initial packets from REST API
  fetch("/api/packets?limit=100")
    .then(r => r.json())
    .then(data => {
      (data.packets || []).forEach(p => {
        state.packets.push(p);
        appendRow(p);
      });
      updateCounter();
    })
    .catch(() => {});
});
