import socket
import os
import random

# Detect if running in Render
USE_MOCK = os.getenv("ENV") == "production"

# Scan ports: real if local, mock if deployed
def scan_ports(ip):
    if USE_MOCK:
        possible_ports = [21, 22, 23, 80, 443, 8080]
        return random.sample(possible_ports, random.randint(1, 4))

    open_ports = []
    common_ports = [21, 22, 23, 80, 443, 8080]
    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            continue
    return open_ports

# Analyze the risk level of open ports
def check_security(open_ports):
    if 23 in open_ports:
        return "⚠️ Telnet Detected (Unsecure)"
    if 80 in open_ports and 443 not in open_ports:
        return "⚠️ HTTP Only (No HTTPS)"
    if len(open_ports) == 0:
        return "✅ No common ports open"
    return "✅ Secure"

# Detect ARP spoofing by checking for duplicate MACs
def detect_arp_spoof(devices):
    macs = [d['mac'] for d in devices]
    return "⚠️ Potential ARP Spoofing Detected!" if len(macs) != len(set(macs)) else "✅ No ARP Spoofing"
