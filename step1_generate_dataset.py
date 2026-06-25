import csv
import random

# Blacklisted IPs list for dataset generation
BLACKLISTED_IPS = [
    "192.168.1.105", "10.0.0.25", "172.16.0.50", "192.168.2.200", "10.10.10.10",
    "203.0.113.45", "198.51.100.22", "185.220.101.34", "91.108.4.1", "45.142.212.100"
]

# Clean/benign IPs list
BENIGN_IPS = [
    "8.8.8.8", "1.1.1.1", "8.8.4.4", "192.168.1.1", "10.0.0.1",
    "172.20.10.5", "172.20.20.30", "10.5.1.12", "10.5.2.24", "192.168.10.15"
]

PORTS = [80, 443, 22, 3389, 8080, 53, 25, 3306]
PROTOCOLS = ["TCP", "UDP"]

def generate_dataset():
    rows = []
    
    # 1. Generate 12 rows with blacklisted IPs
    for _ in range(12):
        # Determine whether src, dst, or both are blacklisted
        scenario = random.choice(["src", "dst", "both"])
        if scenario == "src":
            src = random.choice(BLACKLISTED_IPS)
            dst = random.choice(BENIGN_IPS)
        elif scenario == "dst":
            src = random.choice(BENIGN_IPS)
            dst = random.choice(BLACKLISTED_IPS)
        else:
            src = random.choice(BLACKLISTED_IPS)
            dst = random.choice(BLACKLISTED_IPS)
            
        port = random.choice(PORTS)
        protocol = random.choice(PROTOCOLS)
        num_bytes = random.randint(256, 1500000)
        rows.append([src, dst, port, protocol, num_bytes])
        
    # 2. Generate 10 rows with completely clean/benign IPs
    for _ in range(10):
        src = random.choice(BENIGN_IPS)
        dst = random.choice(BENIGN_IPS)
        # Ensure they are different just to make it realistic
        while src == dst:
            dst = random.choice(BENIGN_IPS)
            
        port = random.choice(PORTS)
        protocol = random.choice(PROTOCOLS)
        num_bytes = random.randint(256, 1500000)
        rows.append([src, dst, port, protocol, num_bytes])
        
    # Shuffle rows to mix benign and suspicious rows
    random.shuffle(rows)
    
    # Write to network_traffic.csv
    with open("network_traffic.csv", mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "dst_ip", "port", "protocol", "bytes"])
        writer.writerows(rows)
        
    print("Generated network_traffic.csv with 22 rows successfully.")

if __name__ == "__main__":
    generate_dataset()
