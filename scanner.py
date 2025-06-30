from scapy.all import ARP, Ether, srp
from utils import scan_ports, check_security, detect_arp_spoof

def scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

if __name__ == "__main__":
    print("📡 Network Security Scanner")
    network = input("Enter IP range (e.g. 192.168.1.0/24): ")

    devices = scan(network)
    
    if not devices:
        print("No devices found. Make sure you're connected to the network.")
        exit()

    print("\nDevices found:")
    for device in devices:
        ports = scan_ports(device['ip'])
        status = check_security(ports)
        print(f"IP: {device['ip']} | MAC: {device['mac']} | Open Ports: {ports} | Status: {status}")

    # ✅ ARP Spoofing check (inside Python file)
    spoof_status = detect_arp_spoof(devices)
    print("\nARP Spoofing Check:", spoof_status)
