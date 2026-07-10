# 🛡 ReconForge  
### Your Frontline Port Recon Scanner

ReconForge is a high-performance reconnaissance framework built from scratch.

It focuses purely on **attack surface discovery and exposure intelligence** — not exploitation.

Recon first. Exploit later.

---

# 🚀 Core Capabilities

- Stealth TCP SYN scanning
- Protocol-aware UDP probing
- Service fingerprinting
- HTTP / HTTPS banner extraction
- TLS certificate inspection
- OS fingerprinting (TTL-based)
- Software detection from banners
- Asynchronous CVE correlation (optional)
- Threaded scanning engine
- JSON report generation
- Custom port range scanning

---

# 🏗 Architecture Overview

ReconForge follows a modular reconnaissance pipeline:

```
                ┌──────────────────────┐
                │      Target Host     │
                └────────────┬─────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
      TCP SYN Scan     UDP Payload Scan    OS Detection
            │                │                │
            └────────────┬───┴───────┬────────┘
                         │           │
                  Banner Grabbing   TTL Analysis
                         │
                  Service Fingerprinting
                         │
                Software Extraction
                         │
              CVE Correlation (Async)
                         │
               Console Output + JSON
```

Each module operates independently to maintain speed and modularity.

---

# 🔄 Recon Workflow

1. Scan initialization  
2. OS detection via TTL heuristic  
3. UDP service probing (protocol-aware payloads)  
4. Threaded TCP SYN scan  
5. Banner grabbing (HTTP/HTTPS/raw)  
6. Software identification  
7. Optional background CVE correlation  
8. Summary output  
9. Optional JSON export  

CVE lookups never block the scanning engine.

---

# 📂 Project Structure

```
ReconForge/
│
├── main.py               # CLI entry point
├── splash.py             # Startup banner + branding
│
├── scanner/
│   ├── engine.py         # TCP + UDP scanning engine
│   ├── banner.py         # HTTP/HTTPS/TLS banner extraction
│   ├── os_detect.py      # TTL-based OS detection
│   ├── udp.py            # Protocol-aware UDP probes
│   ├── cve.py            # Exposure intelligence module
│   └── utils.py          # Shared helpers
│
└── reports/              # JSON output directory
```

Modular design allows independent extension of each capability.

---

# 🖥 Command Line Usage

## Help

```
sudo python main.py --help
```

---

## Default Scan (1–1024)

```
sudo python main.py --target scanme.nmap.org
```

---

## Custom Port Range

```
sudo python main.py --target scanme.nmap.org --start 1 --end 200
```

---

## Enable Exposure Intelligence

```
sudo python main.py --target scanme.nmap.org --cve
```

---

## Full Recon + JSON Export

```
sudo python main.py --target scanme.nmap.org --start 1 --end 200 --cve --json
```

---

# 🌐 UDP Protocol Coverage

ReconForge performs protocol-aware probing on high-value UDP services:

- DNS (53)
- NTP (123)
- SNMP (161)
- TFTP (69)
- SIP (5060)
- LDAP (389)
- NetBIOS (137)
- ISAKMP (500)
- SSDP (1900)
- Memcached (11211)

Only ports within the selected scan range are probed.

---

# 🧠 OS Fingerprinting

OS detection uses TTL-based heuristics:

| TTL Range | Likely OS |
|-----------|-----------|
| ~64       | Linux / Unix |
| ~128      | Windows |
| Other     | Unknown |

Lightweight and non-intrusive.

---

# 🔐 Service & TLS Fingerprinting

For HTTPS services, ReconForge extracts:

- TLS Common Name (CN)
- TLS version
- Cipher suite
- HTTP headers
- Server software

For HTTP services:

- Status line
- Response headers
- Server identification

Software versions are parsed automatically.

---

# 🛡 Exposure Intelligence (Optional)

When `--cve` is enabled:

- Detected software is correlated with public CVE data
- Runs asynchronously
- Filters HIGH / CRITICAL findings
- Does not delay scanning

This is exposure awareness, not exploitation.

---

# 🖨 Sample Output

Real output from a scan against a local target running an HTTP service:

```
Scan started: 2026-07-09 17:07:16
Target      : 127.0.0.1
Port Range  : 7900-8200

[*] OS Guess: Linux / Unix
[+] TCP 8080 OPEN

========== RECON SUMMARY ==========
TCP Open Ports : 1
UDP Exposure  : 0
Web Surface  : Yes
SSH Exposed  : No
HIGH CVEs    : 0
OS           : Linux / Unix
Risk Score   : 1.5 / 10 (LOW)
=================================

Recon Time: 8 seconds

[+] Recon report saved to reconforge_127.0.0.1_20260709_170716.json
```

Banner grabbing + software fingerprinting against a service exposing an OpenSSH banner on a non-standard port:

```
[+] TCP 2222 OPEN
SSH-2.0-OpenSSH_7.2
[!] Identified Software: OpenSSH 7.2

========== RECON SUMMARY ==========
TCP Open Ports : 1
Web Surface  : No
SSH Exposed  : Yes
Risk Score   : 1.5 / 10 (LOW)
=================================
```

Note: exposure detection (`Web Surface` / `SSH Exposed`) is banner-aware, not just port-number-based — a service is correctly flagged even when it isn't running on its conventional port (e.g. OpenSSH on 2222, not just 22).

Resulting JSON report:

```json
{
  "target": "127.0.0.1",
  "duration": 8,
  "os": "Linux / Unix",
  "tcp_ports": [8080],
  "udp_ports": [],
  "software": [],
  "exposure_cves": {},
  "risk": {"score": 1.5, "level": "LOW"}
}
```

---

# 📄 JSON Report Format

Example structure:

```json
{
  "target": "scanme.nmap.org",
  "os": "Linux / Unix",
  "tcp_ports": [22, 80],
  "udp_services": ["53/DNS"],
  "software": {
    "Apache": "2.4.7",
    "OpenSSH": "6.6.1p1"
  },
  "cves": {
    "Apache 2.4.7": ["CVE-2021-44224"]
  },
  "scan_time": "17 seconds"
}
```

Designed for automation pipelines and future integrations.

---

# ⚡ Performance Design

ReconForge achieves speed using:

- ThreadPoolExecutor
- SYN half-open scanning
- Timeout tuning
- Background CVE threads
- Selective UDP probing

Optimized for recon workflows in bug bounty engagements.

---

# 📌 Positioning

ReconForge is a reconnaissance engine.

It is NOT:

- An exploitation framework
- A vulnerability scanner replacement
- A brute-force toolkit

It is designed to map exposure surface quickly and cleanly.

---

# 🛣 Roadmap

- Timing templates (-T0 to -T5 style)
- Service confidence scoring
- ASN and geo lookup
- Web technology fingerprinting
- Screenshot capture module
- HTML reporting
- Plugin-based architecture
- Mass scan mode
- Subdomain integration
- Rate control profiles

---

# ⚠ Legal Disclaimer

Use ReconForge only against systems you own or have explicit permission to test.

Unauthorized scanning may be illegal.

---

## ReconForge  
**Recon First. Exploit Later.**
