import socket
import os
import random

USE_MOCK = os.getenv("ENV") == "production"

def scan_ports(ip):
    if USE_MOCK:
        # 🧪 Return fake ports for demo
        possible_ports = [21, 22, 23, 80, 443, 8080]
        return random.sample(possible_ports, random.randint(1, 4))

    # ✅ Real port scan (local)
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
