# 🔥 Personal Firewall — Cybersecurity Internship Project

A Python-based personal firewall that **monitors, filters, and analyses** network traffic using raw socket packet capture, a priority-based rule engine, and a real-time terminal dashboard.

---

## 📌 Project Overview

| Item | Detail |
|------|--------|
| **Language** | Python 3.8+ |
| **Platform** | Linux (live capture), Windows/macOS (simulation mode) |
| **Internship Track** | Cybersecurity |
| **Skills Covered** | Network Security · Packet Filtering · Protocol Analysis |

---

## 🗂 Project Structure

```
personal_firewall/
├── main.py                    ← Entry point
├── requirements.txt
├── config/
│   ├── firewall_config.json   ← Engine settings
│   └── rules.json             ← Firewall rules (edit to add your own)
├── src/
│   ├── firewall_engine.py     ← Core: capture + parse + rule-match + log
│   ├── packet_simulator.py    ← Demo: synthetic packet generator
│   └── dashboard.py           ← Real-time terminal dashboard
├── tests/
│   └── test_firewall.py       ← Unit tests (pytest)
├── logs/
│   ├── firewall.log           ← Full packet log (auto-created)
│   └── report.json            ← Session statistics (auto-created)
└── docs/
    └── SKILLS_LEARNED.md
```

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/personal-firewall.git
cd personal-firewall
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run (simulation mode — no root needed)
```bash
python main.py
```

### 4. Run with more rounds
```bash
python main.py --rounds 3
```

### 5. Simulate a port scan attack
```bash
python main.py --scan
```

### 6. Simulate a DDoS flood
```bash
python main.py --ddos
```

### 7. Live capture (Linux only, requires root)
```bash
sudo python main.py --live
sudo python main.py --live --iface eth0
```

### 8. Run unit tests
```bash
python -m pytest tests/ -v
```

### 9. View last session stats
```bash
python main.py --stats
```

---

## 📋 Expected Output (Simulation Mode)

```
  ╔══════════════════════════════════════════════════════╗
  ║       🔥  PERSONAL FIREWALL — Cybersecurity Tool     ║
  ║          Packet Filter | Monitor | Analyse           ║
  ╚══════════════════════════════════════════════════════╝

  ✅ [ALLOW]  TCP   192.168.1.10:54321 → 93.184.216.34:443  (rule: allow-https)
  ✅ [ALLOW]  UDP   192.168.1.10:50000 → 8.8.8.8:53         (rule: allow-dns)
  🚫 [BLOCK]  TCP   10.0.0.99:60001   → 192.168.1.10:23     (rule: block-telnet)
  🚫 [BLOCK]  TCP   185.220.101.5     → 192.168.1.10:3389   (rule: block-rdp-external)
  ...

  📊 Total: 48   Allowed: 35   Blocked: 13
```

Log file location: `logs/firewall.log`
Stats report: `logs/report.json`

---

## ⚙️ Adding / Editing Rules

Edit `config/rules.json`. Each rule supports:

| Field | Example | Notes |
|-------|---------|-------|
| `name` | `"block-telnet"` | Unique label |
| `priority` | `1` | Lower = higher priority |
| `action` | `"BLOCK"` or `"ALLOW"` | |
| `protocol` | `"TCP"`, `"UDP"`, `"ICMP"` | Optional |
| `src_ip` | `"45.33.32.156"` | Optional |
| `dst_ip` | `"192.168.1.10"` | Optional |
| `dst_port` | `23` | Optional |
| `src_port` | `54321` | Optional |

Example — block all traffic from a specific IP:
```json
{
  "name": "block-attacker",
  "priority": 1,
  "action": "BLOCK",
  "src_ip": "198.51.100.42"
}
```

---

## 🎓 Skills Learned (Step-by-Step)

### Step 1 — Protocol Analysis (`packet_simulator.py` + `firewall_engine.py`)
You learn how IPv4/TCP/UDP headers are structured byte-by-byte using Python's `struct` module. You craft raw packets and parse them field by field.

### Step 2 — Packet Filtering (`firewall_engine.py` → `RuleEngine`)
You learn how to match packets against ordered rules — the exact same logic used in `iptables` and cloud security groups. Priority ordering, field matching, and default-deny/allow policies.

### Step 3 — Network Security (`main.py` → attack simulations)
You see what real attacks look like: SYN port scans, UDP floods, brute-force RDP attempts — and learn how firewalls detect and block them.

---

## 🔗 GitHub Upload Checklist

- [ ] `git init`
- [ ] `git add .`
- [ ] `git commit -m "Initial commit: Personal Firewall project"`
- [ ] Create repo on GitHub: `personal-firewall`
- [ ] `git remote add origin https://github.com/YOUR_USERNAME/personal-firewall.git`
- [ ] `git push -u origin main`

---

## 🛡 Disclaimer

This tool is for **educational and authorised security testing only**.  
Do not use live capture mode on networks you do not own or have explicit permission to monitor.
