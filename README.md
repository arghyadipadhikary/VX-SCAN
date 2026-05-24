# 🛡️ VX-Scan
<div align="center">

![Status](https://img.shields.io/badge/status-active-22c55e?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge&logo=opensourceinitiative&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![YARA](https://img.shields.io/badge/YARA-Signature_Engine-ef4444?style=for-the-badge)
![NLP](https://img.shields.io/badge/NLP-Semantic_Vectoring-8b5cf6?style=for-the-badge)
![WebSocket](https://img.shields.io/badge/Realtime-WebSocket-f59e0b?style=for-the-badge&logo=socketdotio&logoColor=white)
![Zero FP](https://img.shields.io/badge/False_Positives-Minimized-0ea5e9?style=for-the-badge)

</div>

<br/>

> *"An enterprise-grade, false-positive-resistant security scanner for VS Code Marketplace extensions."*

**VX-SCAN** is a high-performance static and behavioral analysis engine built to detect malicious, obfuscated, and suspicious VS Code extensions before they ever touch a developer's machine. By combining **YARA Signature Matching**, **Shannon Entropy Analysis**, and **NLP Semantic Vectoring**, the engine delivers real-time threat intelligence with a calibrated reputation system that eliminates noise from trusted publishers.

---

## 📡 Engine Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                         VX-SCAN PIPELINE                            │
└─────────────────────────────────────────────────────────────────────┘

  [ INPUT ]                                          [ OUTPUT ]
  ─────────                                          ──────────
  ┌─────────────────┐                           ┌──────────────────────┐
  │  Browser UI     │                           │  Browser UI          │
  │                 │                           │                      │
  │  Target ID:     │                           │  ✅ SAFE             │
  │  ms-python.     │                           │  ⚠️  SUSPICIOUS      │
  │  python         │                           │  🚨 HARMFUL          │
  └────────┬────────┘                           └──────────┬───────────┘
           │ WebSocket                                     │ JSON + PDF
           ▼                                               ▲
  ┌─────────────────────────────────────────────────────────────────┐
  │                      FastAPI Backend                            │
  │                                                                 │
  │  ┌─────────────────┐   ┌──────────────────┐                    │
  │  │ Phase 1         │   │ Phase 2           │                    │
  │  │ Reconnaissance  │──►│ Payload           │                    │
  │  │                 │   │ Acquisition       │                    │
  │  │ • Marketplace   │   │                   │                    │
  │  │   API scrape    │   │ • CDN fetch       │                    │
  │  │ • Publisher ID  │   │ • .vsix unpack    │                    │
  │  │ • Download count│   │ • Strip noise     │                    │
  │  └─────────────────┘   └────────┬──────────┘                   │
  │                                 │                               │
  │                                 ▼                               │
  │  ┌──────────────────────────────────────────────────────────┐  │
  │  │ Phase 3 — Dual-Scan Engine                               │  │
  │  │                                                          │  │
  │  │  ┌─────────────────────┐  ┌─────────────────────────┐   │  │
  │  │  │ YARA Signatures     │  │ Zero-Day Behavioral     │   │  │
  │  │  │                     │  │                         │   │  │
  │  │  │ • rules.yar match   │  │ • Shannon Entropy       │   │  │
  │  │  │ • Language-aware    │  │   threshold: 6.8        │   │  │
  │  │  │   context tuning    │  │ • NLP Semantic          │   │  │
  │  │  │ • False-positive    │  │   Vectoring             │   │  │
  │  │  │   suppression       │  │ • Anomaly score         │   │  │
  │  │  └──────────┬──────────┘  └────────────┬────────────┘   │  │
  │  │             └──────────────┬────────────┘                │  │
  │  └──────────────────────────────────────────────────────────┘  │
  │                               │                                 │
  │                               ▼                                 │
  │  ┌────────────────────────────────────────────────────────┐    │
  │  │ Phase 4 — Heuristic Scoring & Classification           │    │
  │  │                                                        │    │
  │  │  risk_score  ──► Reputation Dampening Protocol         │    │
  │  │                  (Trust Discount: -15 pts)             │    │
  │  │                       │                                │    │
  │  │              ┌────────┴────────┐                       │    │
  │  │           SAFE          SUSPICIOUS          HARMFUL    │    │
  │  └────────────────────────────────────────────────────────┘    │
  │                               │                                 │
  │                               ▼                                 │
  │  ┌────────────────────────────────────────────────────────┐    │
  │  │ Phase 5 — Intelligence Reporting & Cleanup             │    │
  │  │                                                        │    │
  │  │  PDF Report generated → Temp files purged → WS push   │    │
  │  └────────────────────────────────────────────────────────┘    │
  └─────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Engine Phases

### 🔍 Phase 1 — Reconnaissance & Ingestion

When a target ID (e.g. `ms-python.python`) is submitted, the frontend opens a high-speed WebSocket connection to the backend. The engine immediately queries the official **VS Code Marketplace API** to scrape the publisher name and total download count. This data forms a **baseline reputation profile** before a single line of code is touched.

### 📦 Phase 2 — Payload Acquisition & Isolation

The backend dynamically constructs the **Microsoft CDN download URL** and fetches the raw `.vsix` payload. The archive is saved to a secure temporary directory (`/app/temp_uploads`) and extracted. To maximize scan speed and eliminate noise, the engine immediately strips `node_modules` and all non-code assets (images, markdown) — ensuring the scan targets only executable source.

### 🔬 Phase 3 — The Dual-Scan Engine

The engine iterates through every source file and streams telemetry back to the UI in real-time via WebSocket. Two independent analysis engines run in parallel:

**1. Static Signature Matching (YARA)**

Each file is matched against a custom `rules.yar` database of known malware signatures. The engine applies **context-aware language tuning** — it intentionally suppresses generic Node.js execution alerts when scanning Python or C++ extensions, eliminating a major source of false positives that plague naive scanners.

**2. Zero-Day Behavioral Analysis (NLP & Neural Math)**

- **Shannon Entropy** — The engine measures the linguistic randomness of every JavaScript and TypeScript file. Using a carefully calibrated threshold of `6.8`, it distinguishes standard Webpack minification (benign) from deeply encrypted malicious packers (flagged). Standard bundlers fall below the threshold; obfuscated payloads do not.
- **NLP Semantic Vectoring** — A semantic parser scans for clusters of dangerous intent. Isolated network calls or isolated shell commands are acceptable; a dense co-occurrence of `fetch` / `net.Socket` *combined with* `child_process.exec` triggers a weighted **anomaly score**, flagging supply-chain-style exfiltration patterns.

### 📊 Phase 4 — Heuristic Scoring & Classification

After the scan, the engine tallies the final `risk_score` and applies the **Reputation Dampening Protocol**:

- If the publisher is globally verified (e.g., Microsoft, GitHub) with over 1 million installs, a **Trust Discount of −15 points** is applied to the raw score.
- The adjusted score and YARA match results determine the final verdict:

| Verdict | Indicator | Meaning |
|---|---|---|
| **SAFE** | 🟢 Green | No threats detected. Extension is clean. |
| **SUSPICIOUS** | 🟡 Yellow | Uses privileged operations (network, shell) — not malware, but warrants analyst review. |
| **HARMFUL** | 🔴 Red | Critical threat confirmed — unauthorized obfuscation, definitive YARA match, or a high-entropy payload from an untrusted publisher. |

### 📄 Phase 5 — Intelligence Reporting & Cleanup

Once classification is complete, the engine:

1. Generates a formal **PDF Intelligence Report** summarizing all findings. The PDF generator runs inside a failsafe wrapper — if system-level OS dependencies are missing, the app degrades gracefully without crashing.
2. **Securely deletes** the temporary `.vsix` archive and all extracted source files from the server.
3. Transmits the final **JSON verdict payload** and PDF download link over the WebSocket to update the UI.

---

## 🛠️ Tech Stack

<div align="center">

| Layer | Technology |
|---|---|
| **Backend Engine** | Python · FastAPI · Uvicorn |
| **Real-Time Channel** | WebSocket (bidirectional telemetry streaming) |
| **Signature Engine** | YARA · Custom `rules.yar` database |
| **Behavioral Analysis** | Shannon Entropy · NLP Semantic Vectoring |
| **Reputation System** | VS Code Marketplace API · Heuristic Scoring |
| **Reporting** | PDF Intelligence Report · JSON payload |
| **Frontend** | HTML5 · WebSocket client |

</div>

---

## 🛡️ Security Model

```
What the engine flags:                What the engine ignores:
──────────────────────                ───────────────────────
✅ Known malware signatures (YARA)    ❌ node_modules (third-party noise)
✅ High-entropy obfuscated packers    ❌ Media files (images, markdown)
✅ Exfiltration intent clusters       ❌ Standard Webpack minification
✅ Untrusted publisher anomalies      ❌ Verified publisher false positives
✅ Dangerous API co-occurrence        ❌ Isolated, contextually safe calls
```

**False-Positive Resistance** is a first-class design goal. Language-aware YARA tuning, the entropy threshold, and the Reputation Dampening Protocol work together to ensure that extensions like `ms-python.python` — which legitimately execute shell commands — are not flagged by naive pattern matching.

---

## 🗂️ How to Use

1. **Open** the scanner UI in your browser
2. **Enter** a VS Code Marketplace extension ID (e.g., `ms-python.python` or `eamodio.gitlens`)
3. **Watch** the real-time telemetry stream as the engine processes each file
4. **Review** the final verdict — SAFE, SUSPICIOUS, or HARMFUL
5. **Download** the PDF Intelligence Report for a full summary of findings

---

## ⚠️ Disclaimer

This tool is intended for **legitimate security research and enterprise extension vetting**. It does not modify, redistribute, or permanently store any extension payload. All temporary files are securely deleted immediately after analysis. Verdicts are heuristic in nature — a SUSPICIOUS result does not constitute proof of malicious intent and should be reviewed by a qualified analyst.

---

<div align="center">

Developed by **[Arghyadip Adhikary](https://github.com/arghyadipadhikary)** © 2026

</div>
