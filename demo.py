# Runs scanner
from scapy.all import sniff, ARP, TCP, IP
from core import layered_scan
from core.alert import load_persistence, reset_demo_state
from modules.arp_monitor import check_arp
from modules.port_scan_det import check_port_scan
from modules.brute_force_det import analyze_packet
from modules.sniffer import process_packet

def start_scanner(ip):
    layered_scan.user_scan(ip)
    sniff(filter="arp or tcp", prn=process_packet, store=0)

# Runs frontend
from flask import Flask, render_template, request, jsonify
from core.alert import get_frontend_data
from threading import Thread

# this clears the old logs and threat memory every time the frontend starts
reset_demo_state()

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("main.html")

scan_results_data = {}
scan_status = "idle"  

@app.route("/start_scan", methods=["POST"])
def start_scan():
    global scan_results_data, scan_status

    scan_results_data = {}
    scan_status = "running"

    data = request.get_json()
    ip = data.get("ip")

    def run():
        global scan_results_data, scan_status
        scan_results_data = layered_scan.user_scan(ip)
        scan_status = "complete"
        Thread(target=lambda: sniff(filter="arp or tcp", prn=process_packet, store=0), daemon=True).start()

    Thread(target=run, daemon=True).start()

    return jsonify({"status": "scan started", "target": ip})

@app.route("/scan-results")
def scan_results():
    return jsonify({
        "status": scan_status,
        "data": scan_results_data
    })

@app.route("/threats")
def threats():
    return jsonify(get_frontend_data())

if __name__ == "__main__":
    # turning the reloader off keeps it to one clean frontend process
    app.run(debug=True, use_reloader=False)
