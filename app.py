from flask import Flask, render_template, request
from scanner import scan
from utils import scan_ports, check_security, detect_arp_spoof
import ipaddress  # ✅ For validating IP range

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    spoof_status = ""
    error_message = ""

    if request.method == "POST":
        ip_range = request.form.get("ip_range", "").strip()

        try:
            # ✅ Validate input using ipaddress module
            ipaddress.ip_network(ip_range, strict=False)

            devices = scan(ip_range)
            for device in devices:
                ports = scan_ports(device["ip"])
                status = check_security(ports)
                results.append({
                    "ip": device["ip"],
                    "mac": device["mac"],
                    "ports": ports,
                    "status": status
                })

            spoof_status = detect_arp_spoof(devices)

        except ValueError:
            error_message = "❌ Invalid IP range. Use format like 192.168.1.0/24."

    return render_template("index.html", results=results, spoof_status=spoof_status, error_message=error_message)

if __name__ == "__main__":
    app.run(debug=True)
