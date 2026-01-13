from scapy.all import Ether, IP, TCP, UDP, wrpcap
import random
import time

def generate_traffic(filename="traffic.pcap", num_packets=1000):
    print(f"Generating {num_packets} packets for {filename}...")
    packets = []
    
    # Define some "normal" IPs and one "suspicious" IP
    normal_ips = ["192.168.1.5", "192.168.1.6", "192.168.1.7", "198.168.0.1"]
    suspicious_ip = "10.0.0.12" # The one from the prompt example
    
    # 1. Normal Traffic Pattern
    # - Moderate packet size
    # - Port 80, 443 mainly
    # - Balanced TCP/UDP
    for _ in range(int(num_packets * 0.8)):
        src = random.choice(normal_ips)
        dst = "192.168.1.1"
        
        # 70% TCP, 30% UDP
        if random.random() < 0.7:
            proto = TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 8080]))
        else:
            proto = UDP(sport=random.randint(1024, 65535), dport=53)
            
        pkt = Ether() / IP(src=src, dst=dst) / proto / ("X" * random.randint(50, 1000))
        packets.append(pkt)

    # 2. Suspicious Traffic Pattern (Zero-Day-ish)
    # - High frequency (we simulate by adding many packets)
    # - Weird ports
    # - Small or weird packet sizes
    # - High UDP usage or port scanning behavior
    for _ in range(int(num_packets * 0.2)):
        src = suspicious_ip
        dst = "192.168.1.1"
        
        # Random ports (scanning behavior)
        dport = random.randint(1, 10000)
        
        # Weird packet sizes
        payload = "A" * random.randint(10, 1500)
        
        if random.random() < 0.5:
             proto = TCP(sport=random.randint(1024, 65535), dport=dport)
        else:
             proto = UDP(sport=random.randint(1024, 65535), dport=dport)

        pkt = Ether() / IP(src=src, dst=dst) / proto / payload
        packets.append(pkt)

    # 3. Server Responses (192.168.1.1)
    # - Simulating server responding to requests
    for _ in range(int(num_packets * 0.3)):
        src = "192.168.1.1"
        dst = random.choice(normal_ips + [suspicious_ip])
        
        # Responses usually on high random ports back to client, or from 80/443
        if random.random() < 0.8:
            sport = random.choice([80, 443])
            dport = random.randint(1024, 65535)
            proto = TCP(sport=sport, dport=dport)
        else:
            sport = 53
            dport = random.randint(1024, 65535)
            proto = UDP(sport=sport, dport=dport)
            
        pkt = Ether() / IP(src=src, dst=dst) / proto / ("Response" * random.randint(1, 10))
        packets.append(pkt)

    # Shuffle to simulate mixed traffic
    random.shuffle(packets)
    
    # Write to file
    wrpcap(filename, packets)
    print(f"Successfully generated {filename} with normal and suspicious traffic.")

if __name__ == "__main__":
    generate_traffic()
