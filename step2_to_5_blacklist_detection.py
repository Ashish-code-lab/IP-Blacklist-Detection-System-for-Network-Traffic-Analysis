# ============================================================
#  IP Blacklist Detection — Network Traffic Analysis
#  Steps 2 → 5
# ============================================================

# STEP 2 — Import Packages
import pandas as pd
from datetime import datetime


def check_blacklist(row, blacklist):
    """
    Checks if src_ip and/or dst_ip of a connection are in the
    blacklist and returns the corresponding status string.
    """
    src_in = row["src_ip"] in blacklist
    dst_in = row["dst_ip"] in blacklist

    if src_in and dst_in:
        return "SUSPICIOUS (src + dst)"
    elif src_in:
        return "SUSPICIOUS (src)"
    elif dst_in:
        return "SUSPICIOUS (dst)"
    else:
        return "CLEAN"


def main():

    # STEP 3 — Read CSV File as DataFrame
    csv_file = "network_traffic.csv"
    try:
        df = pd.read_csv(csv_file)
    except FileNotFoundError:
        print(f"[ERROR] {csv_file} not found. Run step1_generate_dataset.py first.")
        return

    print("=" * 60)
    print("  IP BLACKLIST DETECTION — NETWORK TRAFFIC ANALYSER")
    print("=" * 60)
    print(f"\n[Step 3] Dataset loaded: {csv_file}")
    print(f"         Rows    : {len(df)}")
    print(f"         Columns : {list(df.columns)}")
    print("\nFirst 5 rows:")
    print(df.head(5).to_string(index=False))

    # STEP 4 — Assign Blacklisted IPs from Ruleset
    BLACKLISTED_IPS = [
        "192.168.1.105",    # Known C2 server
        "10.0.0.25",        # Malware distribution node
        "172.16.0.50",      # Brute-force origin
        "192.168.2.200",    # Data exfiltration host
        "10.10.10.10",      # Port scanner
        "203.0.113.45",     # Phishing infrastructure
        "198.51.100.22",    # Ransomware beacon
        "185.220.101.34",   # Tor exit node
        "91.108.4.1",       # Botnet C2
        "45.142.212.100",   # Exploit kit host
    ]

    print(f"\n[Step 4] Blacklist loaded — {len(BLACKLISTED_IPS)} IPs from ruleset")

    # STEP 5 — Perform Blacklist Check and Mark Suspicious
    df["status"] = df.apply(
        lambda row: check_blacklist(row, BLACKLISTED_IPS), axis=1
    )

    suspicious_df = df[df["status"].str.startswith("SUSPICIOUS")]
    clean_df      = df[df["status"] == "CLEAN"]

    print(f"\n[Step 5] Scan complete:")
    print("=" * 60)
    print(f"  Total records scanned  : {len(df)}")
    print(f"  Suspicious connections : {len(suspicious_df)}")
    print(f"  Clean connections      : {len(clean_df)}")
    print("=" * 60)

    if not suspicious_df.empty:
        print(f"\n{'SRC IP':<20} {'DST IP':<20} {'PORT':<6} {'PROTO':<6} {'BYTES':>10}  STATUS")
        print("-" * 75)
        for _, row in suspicious_df.iterrows():
            print(f"{row['src_ip']:<20} {row['dst_ip']:<20} {row['port']:<6} "
                  f"{row['protocol']:<6} {row['bytes']:>10,}  ⚠  {row['status']}")
    else:
        print("\nNo suspicious connections found.")

    output_file = "network_traffic_analysed.csv"
    df.to_csv(output_file, index=False)

    print(f"\n[Done] Results saved → {output_file}")
    print(f"       Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    main()