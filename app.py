from flask import Flask, render_template, request
from scanner import scan
from utils import scan_ports, check_security, detect_arp_spoof

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    spoof_status = ""
    if request.method == "POST":
        ip_range = request.form.get("iprange")
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

    return render_template("index.html", results=results, spoof_status=spoof_status)

if __name__ == "__main__":
    app.run(debug=True)
