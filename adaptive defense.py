#!/usr/bin/env python3

import subprocess
import time
from collections import defaultdict
from datetime import datetime

# =========================
# CONFIG
# =========================
INTERFACE = "any"              
LOCAL_IP = "192.168.10.10"     
THRESHOLD = 20                   
WINDOW = 10                    

LOG_FILE = "/tmp/adaptive_defense.log"
BLOCKED_FILE = "/tmp/blocked_ips.txt"

# =========================
# STATE
# =========================
syn_times = defaultdict(list)
blocked_ips = set()

# =========================
# HELPERS
# =========================
def log(msg: str) -> None:
    line = f"{datetime.now()} - {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def run(cmd: str) -> None:
    subprocess.call(cmd, shell=True)

def get_mac(ip: str) -> str:
    try:
        out = subprocess.check_output(
            f"ip neigh show {ip}",
            shell=True,
            text=True
        ).strip()
        parts = out.split()
        if "lladdr" in parts:
            return parts[parts.index("lladdr") + 1]
    except Exception:
        pass
    return "UNKNOWN"

def save_blocked(ip: str, mac: str) -> None:
    with open(BLOCKED_FILE, "a") as f:
        f.write(f"{ip} | {mac}\n")

def block_host(ip: str) -> None:
    if ip in blocked_ips:
        return

    mac = get_mac(ip)

    log(f"[!!!] ATTACK DETECTED: IP={ip}, MAC={mac}")

   
    run(f"sudo iptables -I INPUT 1 -s {ip} -j DROP")
    run(f"sudo iptables -I OUTPUT 1 -d {ip} -j DROP")

  
    run(f"sudo iptables -I FORWARD 1 -s {ip} -j DROP")
    run(f"sudo iptables -I FORWARD 1 -d {ip} -j DROP")

    
    if mac != "UNKNOWN":
        run(f"sudo iptables -I INPUT 1 -m mac --mac-source {mac} -j DROP")
        run(f"sudo iptables -I FORWARD 1 -m mac --mac-source {mac} -j DROP")


    run(f"sudo ip neigh del {ip} dev enx00008d9c465e")

    blocked_ips.add(ip)
    save_blocked(ip, mac)

    log(f"[✔] BLOCKED: IP={ip}, MAC={mac}")

def process_syn(src_ip: str) -> None:
    if src_ip == LOCAL_IP:
        return

    if src_ip in blocked_ips:
        return

    now = time.time()

    syn_times[src_ip].append(now)
    syn_times[src_ip] = [t for t in syn_times[src_ip] if now - t <= WINDOW]

    count = len(syn_times[src_ip])
    log(f"[+] SYN from {src_ip} | count={count}")

    if count >= THRESHOLD:
        log(f"[DEBUG] threshold reached for {src_ip}")
        block_host(src_ip)

# =========================
# MAIN
# =========================
def main() -> None:
    log("[*] Adaptive Defense started")
    log(f"[*] Interface: {INTERFACE}")
    log(f"[*] Local IP ignored: {LOCAL_IP}")
    log(f"[*] Threshold: {THRESHOLD} SYN in {WINDOW} sec")

    cmd = [
        "sudo",
        "tcpdump",
        "-n",
        "-l",
        "-i",
        INTERFACE,
        "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    try:
        for line in proc.stdout:
            line = line.strip()

           
            if " IP " in line:
                ip_part = line.split(" IP ", 1)[1]
            elif line.startswith("IP "):
                ip_part = line[3:]
            else:
                continue

            parts = ip_part.split()
            if len(parts) < 3:
                continue

            src_with_port = parts[0]
            src_parts = src_with_port.split(".")

            if len(src_parts) < 5:
                continue

            src_ip = ".".join(src_parts[:4])
            process_syn(src_ip)

    except KeyboardInterrupt:
        log("[!] Adaptive Defense stopped by user")
        proc.terminate()

if __name__ == "__main__":
    main()