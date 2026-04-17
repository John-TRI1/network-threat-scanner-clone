import os
import re
from datetime import datetime

LOG_FILE = 'threat_log.txt'
SCORES = {'ARP_SPOOF': 50, 'PORT_SCAN': 20, 'SYN_FLOOD': 30, 'RST_FLOOD': 10}

threats = {}

def load_persistence():
    """Reads the log file to resume scores from the last session."""
    if not os.path.exists(LOG_FILE):
        return

    # Regex matches: [HH:MM:SS] IP | ATTACK_TYPE | Score: NUM
    pattern = re.compile(r"\[.*?\] ([\d\.]+) \| (\w+) \| Score: (\d+)")
    
    with open(LOG_FILE, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip, attack, score = match.groups()
                if ip not in threats:
                    threats[ip] = {'score': 0, 'dst': 'N/A', 'port': 'N/A', 'attacks': set()}
                
                # Keep the highest score found in logs for that IP
                threats[ip]['score'] = max(threats[ip]['score'], int(score))
                threats[ip]['attacks'].add(attack)
    print(f"[*] Loaded persistence for {len(threats)} hosts from {LOG_FILE}")

def get_security_status(score):
    if score < 40: return ("STAGING", "Monitor closely")
    elif score < 100: return ("SUSPICIOUS", "Restrict bandwidth")
    elif score < 200: return ("DANGEROUS", "Isolate host")
    else: return ("HOSTILE", "KICK FROM NETWORK")

def log_alert(alert_type, src_ip, dst_ip="N/A", port="N/A"):
    if src_ip not in threats:
        threats[src_ip] = {'score': 0, 'dst': dst_ip, 'port': port, 'attacks': set()}
    
    threats[src_ip]['score'] += SCORES.get(alert_type, 0)
    threats[src_ip]['dst'] = dst_ip
    threats[src_ip]['port'] = port
    threats[src_ip]['attacks'].add(alert_type)

    score = threats[src_ip]['score']
    status, action = get_security_status(score)
    timestamp = datetime.now().strftime('%H:%M:%S')

    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"[{timestamp}] {src_ip} | {alert_type} | Score: {score}")
    print("="*105)
    print(f"{'SOURCE IP':<15} | {'SCORE':<5} | {'STATUS':<12} | {'RECOMMENDED ACTION':<25} | {'ATTACKS'}")
    print("-" * 105)
    
    # Corrected lambda sorting to use x[1] for the data dictionary
    for ip, data in sorted(threats.items(), key=lambda x: x[1]['score'], reverse=True):
        s, a = get_security_status(data['score'])
        attacks = ", ".join(data['attacks'])
        print(f"{ip:<15} | {data['score']:<5} | {s:<12} | {a:<25} | {attacks}")
    print("="*105)

    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {src_ip} | {alert_type} | Score: {score}\n")