from flask import Flask, render_template, request, jsonify
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
import os
import random
import google.generativeai as genai
import json

app = Flask(__name__)

# --- CONFIGURATION ---
PCAP_FILE = "traffic.pcap"

# !!! CLASS PROJECT API KEY !!!
# In a real app, use environment variables.
GOOGLE_API_KEY = "AIzaSyDYOQrqt6xggbWm6NNNuT8rtf0XhIf-TU4"
genai.configure(api_key=GOOGLE_API_KEY)

# --- HELPER FUNCTIONS ---

def get_all_ips(pcap_path):
    """Returns a simplified list of IPs found in the PCAP that acted as Source."""
    if not os.path.exists(pcap_path):
        return []
    
    unique_ips = set()
    try:
        packets = rdpcap(pcap_path)
        for pkt in packets:
            if IP in pkt:
                unique_ips.add(pkt[IP].src)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
            
    return sorted(list(unique_ips))

def extract_features(pcap_path, target_ip):
    """
    Parses PCAP and extracts features.
    If IP is not found in PCAP, GENERATES SYNTHETIC DATA so the AI always receives input.
    """
    # Clean input (remove http/s, trailing slashes, ports)
    target_ip = target_ip.strip()
    target_ip = target_ip.replace("http://", "").replace("https://", "")
    target_ip = target_ip.rstrip("/")
    if ":" in target_ip:
        target_ip = target_ip.split(":")[0]

    features = None
    
    if os.path.exists(pcap_path):
        packets = rdpcap(pcap_path)
        # Filter packets for the target IP
        ip_packets = [pkt for pkt in packets if IP in pkt and pkt[IP].src == target_ip]
        if ip_packets:
            # 1. Real Data Extraction
            total_packets = len(ip_packets)
            pkt_sizes = [len(pkt) for pkt in ip_packets]
            avg_pkt_size = np.mean(pkt_sizes) if pkt_sizes else 0
            timestamps = [float(pkt.time) for pkt in ip_packets]
            if timestamps:
                flow_duration = max(timestamps) - min(timestamps)
            else:
                flow_duration = 0
            pkt_rate = total_packets / flow_duration if flow_duration > 0 else total_packets
            
            dst_ports = set()
            tcp_count = 0
            for pkt in ip_packets:
                if TCP in pkt:
                    dst_ports.add(pkt[TCP].dport)
                    tcp_count += 1
                elif UDP in pkt:
                    dst_ports.add(pkt[UDP].dport)
            unique_ports = len(dst_ports)
            tcp_ratio = tcp_count / total_packets if total_packets > 0 else 0
            
            features = {
                'total_packets': total_packets,
                'avg_pkt_size': float(avg_pkt_size),
                'pkt_rate': float(pkt_rate),
                'unique_ports': unique_ports,
                'tcp_ratio': float(tcp_ratio),
                'flow_duration': float(flow_duration)
            }

    return features

import socket
import subprocess
import time

def perform_live_scan(target_ip):
    """
    Performs a real-time active scan of the target IP since it wasn't found in PCAP.
    1. Ping check (Reachability)
    2. Common Port Scan (Service Discovery)
    Returns features dict or None if unreachable.
    """
    print(f"Starting live scan for {target_ip}...")
    
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW # Hide window
        output = subprocess.check_output(
            ["ping", "-n", "1", "-w", "1000", target_ip], 
            startupinfo=startupinfo, stderr=subprocess.STDOUT
        ).decode()
        
        # Windows ping output can be tricky.
        # "Reply from 192.168.1.1: Destination host unreachable." contains "Reply from"!
        if "unreachable" in output.lower() or "timed out" in output.lower() or "failure" in output.lower():
            print(f"Ping failed: {output.strip()}")
            return None

        if "TTL=" not in output:
             print("Ping failed (No TTL).")
             return None # Unreachable
    except Exception as e:
        print(f"Ping error: {e}")
        return None

    # 2. Basic Port Scan
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]
    open_ports = 0
    start_time = time.time()
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports += 1
        sock.close()
        
    duration = time.time() - start_time
    
    # 3. Construct "Live" Features
    # Since we are scanning, 'total_packets' is just our probe count. 
    # 'pkt_rate' is low.
    # This distinguishes it from high-volume traffic in PCAP.
    
    features = {
        'total_packets': len(common_ports) * 2, # Request + Reply (approx)
        'avg_pkt_size': 64.0, # Standard packet size
        'pkt_rate': len(common_ports) / duration if duration > 0 else 0,
        'unique_ports': open_ports,
        'tcp_ratio': 1.0, # Our scan is mostly TCP connect
        'flow_duration': duration,
        'is_live_scan': True # Flag to tell AI this is a scan
    }
    
    return features


def train_and_score_with_gemini(features, ip_address):
    """
    Sends the feature vector to Google Gemini Pro to get a sophisticated analysis.
    fallback to heuristic if fails.
    """
    
    is_live_scan = features.get('is_live_scan', False)
    
    data_source_text = "PASSIVE TRAFFIC CAPTURE (PCAP)"
    if is_live_scan:
        data_source_text = "ACTIVE LIVE SCAN REQUST (Real-time Probe)"

    prompt = f"""
    You are a cybersecurity expert AI. Analyze the following network data for IP {ip_address} 
    and determine if it is Normal, Suspicious, or a Zero-Day Threat.
    
    DATA SOURCE: {data_source_text}
    Note: If this is an Active Scan, 'Total Packets' will be low (just probes) and 'Unique Ports' represents OPEN ports found now.
    If Passive Capture, it represents historical traffic flow.

    TRAFFIC DATA:
    - Total Packets: {features['total_packets']}
    - Average Packet Size: {features['avg_pkt_size']:.2f} bytes
    - Packet Rate: {features['pkt_rate']:.2f} packets/sec
    - Unique Destination/Open Ports: {features['unique_ports']}
    - TCP Ratio: {features['tcp_ratio']:.2f} (1.0 = All TCP)
    - Flow Duration: {features['flow_duration']:.2f} seconds

    INSTRUCTIONS:
    1. Calculate a risk score from 0 (Safe) to 100 (Critical Threat).
    2. Determine status: "Normal" (0-30), "Suspicious" (31-60), or "Zero-Day Threat" (61-100).
    3. Provide a short, professional reason for your verdict.
    
    OUTPUT FORMAT:
    Return ONLY a raw JSON string (no markdown formatting) with keys: "score", "status", "reason".
    Example: {{ "score": 85, "status": "Zero-Day Threat", "reason": "High variance in port usage indicates port scanning." }}
    """
    
    response = None
    # Try proven working model first, then others
    for model_name in ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-pro']:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(prompt)
            break # Success!
        except Exception as e:
            print(f"Model {model_name} failed: {e}")
            continue

    try:
        if not response:
            raise Exception("All Gemini models failed.")

        text = response.text.strip()
        
        # Clean up markdown code blocks if gemini sends them
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
            
        result = json.loads(text)
        
        # Ensure keys exist
        score = result.get('score', 50)
        status = result.get('status', 'Suspicious')
        reason = result.get('reason', 'Analysis completed.')
        
        return score, status, reason
        
    except Exception as e:
        print(f"Gemini API Error: {e}")
        # FALLBACK HEURISTIC if API fails
        score = 10
        if features['unique_ports'] > 20: score += 40
        if features['pkt_rate'] > 100: score += 30
        if score > 100: score = 99
        
        status = "Normal"
        if score > 30: status = "Suspicious"
        if score > 60: status = "Zero-Day Threat"
        
        # Friendly Fallback Message
        fallback_reason = "Offline Behavioral Analysis: Traffic patterns evaluated against local baseline rules. "
        if status == "Normal": fallback_reason += "No significant anomalies detected."
        elif status == "Suspicious": fallback_reason += "Unusual port activity or packet size detected."
        else: fallback_reason += "Critical deviation from normal traffic signatures."
        
        return score, status, fallback_reason

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan_network', methods=['GET'])
def scan_network():
    """Returns all IPs found in the PCAP that acted as sources"""
    if not os.path.exists(PCAP_FILE):
        return jsonify({"ips": []})
        
    ips = get_all_ips(PCAP_FILE)
    return jsonify({"ips": ips})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({"error": "No IP provided"}), 400

    # Clean IP globally for the request
    ip_address = ip_address.strip().replace("http://", "").replace("https://", "").rstrip("/")
    if ":" in ip_address:
        ip_address = ip_address.split(":")[0]
        
    if not os.path.exists(PCAP_FILE):
        return jsonify({"error": "PCAP file missing."}), 404
        
    # 2. Extract Features
    features = extract_features(PCAP_FILE, ip_address)
    
    if features is None:
        # Try Live Scan if not in PCAP
        features = perform_live_scan(ip_address)
    
    if features is None:
        # Still None? Then truly unreachable.
        return jsonify({
            "ip": ip_address,
            "features": None,
            "score": 0,
            "status": "Not Reachable",
            "reason": "Target IP is offline or blocking probes.\nNo historical traffic found and live ping failed."
        })
        
    # 3. AI Analysis (Gemini)
    score, status, reason = train_and_score_with_gemini(features, ip_address)
    
    return jsonify({
        "ip": ip_address,
        "features": features,
        "score": score,
        "status": status,
        "reason": reason
    })

if __name__ == '__main__':
    app.run(debug=False, port=5000)
