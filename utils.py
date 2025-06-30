import socket

def scan_ports(ip, ports=[21, 22, 23, 80, 443, 445]):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except:
            continue
        finally:
            sock.close()
    return open_ports

def check_security(open_ports):
    insecure_ports = [21, 23, 445]  # FTP, Telnet, SMB
    warnings = [port for port in open_ports if port in insecure_ports]
    if warnings:
        return f"⚠️ Insecure ports detected: {warnings}"
    return "✅ Secure"

def detect_arp_spoof(devices):
    macs = [d['mac'] for d in devices]
    if len(macs) != len(set(macs)):
        return "⚠️ Potential ARP Spoofing Detected! Duplicate MAC addresses found."
    return "✅ No ARP Spoofing Detected"
