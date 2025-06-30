from flask import Flask, render_template, request
from scanner import scan
from utils import scan_ports, check_security, detect_arp_spoof

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    spoof_status = ""
    if request.method == "POST":
        # ✅ Use .get with fallback and .strip to avoid None or whitespace issues
        ip_range = request.form.get("ip_range", "").strip()

        if ip_range:  # ✅ Prevent crash if field is empty
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
        else:
            spoof_status = "❗ Please enter a valid IP range."

    return render_template("index.html", results=results, spoof_status=spoof_status)

if __name__ == "__main__":
    app.run(debug=True)
