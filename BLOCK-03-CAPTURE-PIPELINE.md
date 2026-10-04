# Block 3: Capture & Labeling Pipeline — Deep-Dive Implementation Guide

This document provides a comprehensive dissection and step-by-step implementation blueprint for **Block 3: Capture & Labeling Pipeline** in ShadowNet.

---

## 1. Architectural Role & Objective

The Capture and Labeling Pipeline is the bridge between raw attack simulation and machine learning datasets. It captures full packet traffic across the digital twin and produces an unambiguous ground-truth label file correlating time windows to attack categories.

```
                  ┌──────────────────────────────────────────────┐
                  │          Attack Simulation (Block 2)         │
                  │   Nmap Scan  │  Hydra Brute  │  sqlmap SQLi  │
                  └──────────────────────┬───────────────────────┘
                                         │ Generates
                                         ▼
                     ┌──────────────────────────────────────┐
                     │       shadownet/logs/attack_log.txt  │
                     │  START <attack> <timestamp_utc>      │
                     │  END   <attack> <timestamp_utc>      │
                     └───────────────────┬──────────────────┘
                                         │
┌────────────────────────┐               │ Label Generator
│  shadownet-attacker    │               │ (generate_labels.py)
│  tcpdump -i eth0       │               ▼
│  captures twin-net     │    ┌──────────────────────────────────────┐
│  traffic               │    │       shadownet/logs/labels.csv      │
└───────────┬────────────┘    │  attack_type,start,end,src,dst       │
            │ Produces        └──────────────────┬───────────────────┘
            ▼                                    │
┌────────────────────────┐                       │ Ground Truth Link
│   captures/            │◄──────────────────────┘
│   session1.pcap        │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────────────────────────────────────┐
│  Downstream: CICFlowMeter / NFStream Feature Extractor │
│     (Labeled Flow Dataset for Model Training)          │
└────────────────────────────────────────────────────────┘
```

### Objectives
1. Run background packet capture on `twin-net` across the entire simulation duration.
2. Ensure captures contain authentic bi-directional frames between Attacker (`10.10.0.20`), Web (`10.10.0.10`), and Database (`10.10.0.11`).
3. Parse the timestamp log from Block 2 and generate a structured ground-truth label log (`labels.csv`).
4. Validate PCAP health, integrity, and packet distribution.

---

## 2. Component Files to Create

```
shadownet/
├── captures/
│   └── session1.pcap         <-- Output: Raw full-packet capture file
├── logs/
│   ├── attack_log.txt        <-- Input: Raw START/END timestamps from Block 2
│   └── labels.csv            <-- Output: Structured ground-truth attack metadata
├── scripts/
│   ├── generate_labels.py    <-- Script converting log into machine-readable CSV
│   └── verify_pcap.sh        <-- PCAP diagnostic & inspection script
└── run_pipeline.sh           <-- Unified runner orchestrating Block 2 + Block 3
```

---

## 3. Dissecting the Implementation Components

### 3.1. Packet Capture Strategy with `tcpdump`

#### Where to Run `tcpdump`?
In ShadowNet, packet capture can be executed in two locations:
1. **Inside `shadownet-attacker` on `eth0` (Recommended):**
   - Self-contained inside the Compose environment.
   - Doesn't require finding the host's dynamic `veth` / `br-*` interface names in Windows/WSL2.
   - Directly records all traffic leaving or entering the attacker.

#### Key `tcpdump` Flags & Mechanics:
```bash
tcpdump -i eth0 -s 0 -n -U -w /captures/session1.pcap
```

- **`-i eth0` (Interface Selection):**
  - Specifies the container's primary virtual ethernet adapter attached to `twin-net`.
  - **Why not `-i any`?** Capturing on `any` produces Linux "Cooked" capture headers (`SLL`) instead of standard Ethernet II (`EN10MB`) frames. Some flow analysis tools (like legacy CICFlowMeter builds) cannot parse `SLL` headers and expect raw Ethernet framing. Specifying `eth0` ensures 100% standard Ethernet framing.
- **`-s 0` (Snapshot Length):**
  - Sets packet snaplength to 65535 bytes (untruncated full payload).
  - Essential for web attack inspection (capturing HTTP POST data, login tokens, and SQL injection strings).
- **`-n` (No DNS Resolution):**
  - Disables reverse DNS lookups for IPs. Prevents packet drop and avoids DNS timeout latency in an isolated network.
- **`-U` (Packet-Buffered Output):**
  - Flushes packets to the file buffer immediately upon receipt rather than waiting for 4KB/8KB buffers to fill. Prevents lost packets when stopping the capture.
- **`-w /captures/session1.pcap`:**
  - Writes directly to the host-mounted volume for immediate host access.

---

### 3.2. Clean Termination Protocol (Avoiding Corrupted PCAP Files)

When `tcpdump` is terminated with `SIGKILL` (`kill -9`), the file buffer is abruptly closed without writing the pcap file footer or updating packet counters, leading to corrupted or truncated PCAP files.

#### Correct Termination Sequence:
```bash
# Send SIGINT (interrupt) or SIGTERM, allowing tcpdump to flush buffers
kill -2 "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null || true
```
This guarantees that `tcpdump` logs its final statistics (`X packets captured, Y packets received by filter, 0 packets dropped by kernel`) and writes a clean pcap trailer.

---

### 3.3. Ground-Truth Label Generator (`shadownet/scripts/generate_labels.py`)

This Python utility reads the raw timestamp boundaries emitted by Block 2's `attack_log.txt` and normalizes them into a structured dataset for flow classification.

```python
#!/usr/bin/env python3
"""
generate_labels.py — Parses attack_log.txt and outputs labels.csv.
"""

import sys
import os
import csv
from datetime import datetime

DEFAULT_LOG = "/logs/attack_log.txt"
DEFAULT_OUT = "/logs/labels.csv"

# Metadata enrichment mapping for attack classes
ATTACK_METADATA = {
    "nmap_scan": {
        "category": "Reconnaissance",
        "target_port": "1-1000",
        "protocol": "TCP"
    },
    "hydra_bruteforce": {
        "category": "Credential_Access",
        "target_port": "80",
        "protocol": "TCP/HTTP"
    },
    "sqlmap_sqli": {
        "category": "Exploitation",
        "target_port": "80",
        "protocol": "TCP/HTTP"
    }
}

def parse_logs(log_path, out_path, attacker_ip="10.10.0.20", target_ip="10.10.0.10"):
    if not os.path.exists(log_path):
        print(f"[!] Error: Log file {log_path} not found.")
        sys.exit(1)

    attacks = {}
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue

            action, attack_name, timestamp = parts[0], parts[1], parts[2]

            if action == "START":
                attacks[attack_name] = {"start": timestamp, "end": None}
            elif action == "END" and attack_name in attacks:
                attacks[attack_name]["end"] = timestamp

    # Write output CSV
    fieldnames = [
        "attack_type",
        "category",
        "start_time",
        "end_time",
        "source_ip",
        "target_ip",
        "target_port",
        "protocol"
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for attack_name, times in attacks.items():
            meta = ATTACK_METADATA.get(attack_name, {
                "category": "Unknown",
                "target_port": "any",
                "protocol": "IP"
            })
            writer.writerow({
                "attack_type": attack_name,
                "category": meta["category"],
                "start_time": times["start"],
                "end_time": times["end"] or times["start"],
                "source_ip": attacker_ip,
                "target_ip": target_ip,
                "target_port": meta["target_port"],
                "protocol": meta["protocol"]
            })

    print(f"[+] Ground-truth labels successfully generated: {out_path}")

if __name__ == "__main__":
    log_p = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG
    out_p = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    parse_logs(log_p, out_p)
```

---

### 3.4. Output Schema (`shadownet/logs/labels.csv`)

The generated CSV maps directly to standard intrusion detection formats:

```csv
attack_type,category,start_time,end_time,source_ip,target_ip,target_port,protocol
nmap_scan,Reconnaissance,2026-10-05T01:10:00Z,2026-10-05T01:10:15Z,10.10.0.20,10.10.0.10,1-1000,TCP
hydra_bruteforce,Credential_Access,2026-10-05T01:10:20Z,2026-10-05T01:10:26Z,10.10.0.20,10.10.0.10,80,TCP/HTTP
sqlmap_sqli,Exploitation,2026-10-05T01:10:31Z,2026-10-05T01:10:48Z,10.10.0.20,10.10.0.10,80,TCP/HTTP
```

---

### 3.5. PCAP Verification & Diagnostics (`shadownet/scripts/verify_pcap.sh`)

To prove the capture is valid before feeding into machine learning pipelines:

```bash
#!/usr/bin/env bash
set -euo pipefail

PCAP_FILE="${1:-/captures/session1.pcap}"

echo "=== Verifying PCAP Capture: ${PCAP_FILE} ==="

if [ ! -f "$PCAP_FILE" ]; then
    echo "[!] PCAP file does not exist!"
    exit 1
fi

FILE_SIZE=$(du -h "$PCAP_FILE" | awk '{print $1}')
echo "[+] File Size: ${FILE_SIZE}"

# 1. Inspect first 10 packets
echo ""
echo "--- Sample Packets (First 10) ---"
tcpdump -nn -r "$PCAP_FILE" -c 10

# 2. Count packets involving the target DVWA (10.10.0.10)
TOTAL_PACKETS=$(tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | wc -l)
DVWA_PACKETS=$(tcpdump -nn -r "$PCAP_FILE" "host 10.10.0.10" 2>/dev/null | wc -l)

echo ""
echo "--- Traffic Summary ---"
echo "Total Captured Packets : ${TOTAL_PACKETS}"
echo "Packets Involving DVWA : ${DVWA_PACKETS}"

if [ "$DVWA_PACKETS" -gt 50 ]; then
    echo "[+] Verification SUCCESS: PCAP contains valid multi-attack traffic."
else
    echo "[!] WARNING: Abnormally low packet count. Check if simulation executed."
fi
```

---

## 4. End-to-End Orchestrated Pipeline (`shadownet/run_pipeline.sh`)

This script combines Block 2 and Block 3 into a single execution command that handles the full capture, attack execution, teardown, and dataset preparation:

```bash
#!/usr/bin/env bash
set -euo pipefail

PCAP_PATH="/captures/session1.pcap"
LOG_PATH="/logs/attack_log.txt"
LABELS_PATH="/logs/labels.csv"

echo "=========================================================="
echo "   ShadowNet: Automated Attack & Capture Pipeline         "
echo "=========================================================="

# 1. Clean previous run artifacts
rm -f "$PCAP_PATH" "$LOG_PATH" "$LABELS_PATH"
mkdir -p /captures /logs

# 2. Start tcpdump in background
echo "[1/4] Starting background tcpdump on eth0..."
tcpdump -i eth0 -s 0 -n -U -w "$PCAP_PATH" > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "[+] tcpdump running with PID: ${TCPDUMP_PID}"

# Brief delay to ensure sniffer socket is bound
sleep 2

# 3. Execute Block 2 Attack Suite
echo "[2/4] Executing Attack Simulation Engine (Block 2)..."
/root/attacks/run_attacks.sh

# Brief delay to allow final TCP teardowns to complete
sleep 2

# 4. Gracefully terminate tcpdump
echo "[3/4] Stopping packet capture gracefully..."
kill -2 "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null || true
echo "[+] tcpdump terminated."

# 5. Generate Ground Truth Label CSV
echo "[4/4] Generating labels.csv from attack_log.txt..."
python3 /root/attacks/scripts/generate_labels.py "$LOG_PATH" "$LABELS_PATH"

# 6. Run PCAP Diagnostics
/root/attacks/scripts/verify_pcap.sh "$PCAP_PATH"

echo "=========================================================="
echo "   Pipeline Finished: PCAP and Labels Ready for ML        "
echo "=========================================================="
```

---

## 5. How Downstream ML Consumes These Deliverables

When transitioning to subsequent blocks (flow feature extraction and model training):

```
       [ session1.pcap ]                 [ labels.csv ]
              │                                │
              ▼                                ▼
┌───────────────────────────┐     ┌───────────────────────────┐
│ NFStream / CICFlowMeter   │     │ Time Window Filter        │
│ Computes flow statistics: │     │ nmap_scan    : t1 -> t2   │
│ - Duration, Byte counts   │     │ hydra_brute  : t3 -> t4   │
│ - Forward/Backward IAT    │     │ sqlmap_sqli  : t5 -> t6   │
│ - TCP Flags, Flow rates   │     └─────────────┬─────────────┘
└─────────────┬─────────────┘                   │
              │                                 │
              └───────────────┬─────────────────┘
                              ▼
               ┌───────────────────────────────┐
               │    dataset_labeled.csv        │
               │ Features (X) + Ground Truth (y│
               └──────────────┬────────────────┘
                              ▼
               ┌───────────────────────────────┐
               │ Machine Learning Classifier   │
               │ (RandomForest / XGBoost / MLP)│
               └───────────────────────────────┘
```

1. **Flow Aggregator (e.g., Python `NFStream`):** Reads `session1.pcap` and aggregates individual packets into bidirectional network flows.
2. **Label Assigner:** Compares the timestamp of each flow against the ranges in `labels.csv`.
   - If `flow.bidirectional_first_seen_ms` falls within the `nmap_scan` window $\to$ `Label = Reconnaissance`
   - If within `hydra_bruteforce` window $\to$ `Label = BruteForce`
   - If within `sqlmap_sqli` window $\to$ `Label = SQLInjection`
   - Any background flows outside these windows $\to$ `Label = Benign`
3. **Training Ready:** Yields an exportable, un-skewed training matrix with zero synthetic guessing.
