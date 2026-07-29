"""
MicroAPI Guard - Dataset Generation Script
============================================
Automates the full dataset generation workflow:
  1. Cleans old JSONL log file
  2. Runs Locust in headless mode
  3. Reports dataset statistics (normal vs attack counts)

Usage:
  python generate_dataset.py                     # Default: 50 users, 10 minutes
  python generate_dataset.py --users 100 --time 20m
"""

import subprocess
import sys
import os
import json
import argparse
from collections import Counter


# ======================== CONFIG ========================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCUSTFILE = os.path.join(SCRIPT_DIR, "locustfile.py")
GATEWAY_URL = "http://localhost:5000"
DEFAULT_USERS = 50
DEFAULT_SPAWN_RATE = 5
DEFAULT_RUN_TIME = "10m"

# JSONL file location: src/data/api_traffic_features.jsonl
# This matches the bind mount in docker-compose.yml (./data:/app/data)
DATA_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "data"))
JSONL_FILE = os.path.join(DATA_DIR, "api_traffic_features.jsonl")


def clean_old_data():
    """Remove old JSONL file to start fresh."""
    if os.path.exists(JSONL_FILE):
        os.remove(JSONL_FILE)
        print(f"[DATASET] Cleaned old dataset: {JSONL_FILE}")
    else:
        print(f"[DATASET] No old dataset found. Starting fresh.")


def run_locust(users: int, spawn_rate: int, run_time: str):
    """Run Locust in headless mode."""
    cmd = [
        sys.executable, "-m", "locust",
        "-f", LOCUSTFILE,
        "--host", GATEWAY_URL,
        "--headless",
        "-u", str(users),
        "-r", str(spawn_rate),
        "--run-time", run_time,
    ]
    print(f"\n[DATASET] Starting Locust traffic generation...")
    print(f"[DATASET] Users: {users} | Spawn Rate: {spawn_rate}/s | Duration: {run_time}")
    print(f"[DATASET] Target: {GATEWAY_URL}")
    print(f"[DATASET] Command: {' '.join(cmd)}")
    print("=" * 60)

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n[DATASET] Locust exited with error code {e.returncode}")
    except KeyboardInterrupt:
        print(f"\n[DATASET] Interrupted by user. Partial dataset saved.")


def report_statistics():
    """Read the JSONL file and print dataset statistics."""
    if not os.path.exists(JSONL_FILE):
        print(f"\n[DATASET] WARNING: JSONL file not found at {JSONL_FILE}")
        print("[DATASET] Make sure the gateway is running (docker-compose up).")
        print("[DATASET] The gateway writes to src/data/api_traffic_features.jsonl")
        return

    total = 0
    label_counts = Counter()
    method_counts = Counter()
    path_counts = Counter()
    body_sizes = []

    with open(JSONL_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                total += 1
                label_counts[record.get("label", "unknown")] += 1
                method_counts[record.get("http_method", "unknown")] += 1
                path = record.get("http_path", "unknown")
                path_counts[path] += 1
                body_sizes.append(record.get("request_body_size", 0))
            except json.JSONDecodeError:
                continue

    if total == 0:
        print("\n[DATASET] WARNING: JSONL file is empty. No records found.")
        return

    print("\n" + "=" * 60)
    print("         DATASET GENERATION REPORT")
    print("=" * 60)
    print(f"\n  Total Records : {total:,}")
    print(f"  File Location : {JSONL_FILE}")
    print(f"  File Size     : {os.path.getsize(JSONL_FILE) / 1024:.1f} KB")

    print(f"\n  --- Label Distribution ---")
    for label, count in sorted(label_counts.items()):
        pct = (count / total * 100) if total else 0
        bar = "█" * int(pct / 2)
        print(f"  {label:10s} : {count:6,} ({pct:5.1f}%) {bar}")

    print(f"\n  --- HTTP Method Distribution ---")
    for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
        pct = (count / total * 100) if total else 0
        print(f"  {method:8s} : {count:6,} ({pct:5.1f}%)")

    print(f"\n  --- Top 10 Paths ---")
    for path, count in path_counts.most_common(10):
        pct = (count / total * 100) if total else 0
        print(f"  {path:35s} : {count:6,} ({pct:5.1f}%)")

    if body_sizes:
        avg_size = sum(body_sizes) / len(body_sizes)
        max_size = max(body_sizes)
        print(f"\n  --- Body Size Stats ---")
        print(f"  Average : {avg_size:,.0f} bytes")
        print(f"  Max     : {max_size:,} bytes")

    print("\n" + "=" * 60)

    # Sanity checks
    normal = label_counts.get("normal", 0)
    attack = label_counts.get("attack", 0)
    unknown = label_counts.get("unknown", 0)

    if total < 1000:
        print("  ⚠️  Dataset is small. Consider running longer (--time 20m).")
    if unknown > 0:
        print(f"  ⚠️  {unknown} records have 'unknown' label (not from Locust).")
    if normal == 0 or attack == 0:
        print("  ❌ Missing labels! Check if Locust is sending X-Ground-Truth header.")
    if attack > 0 and normal > 0:
        ratio = normal / attack
        print(f"  ✅ Normal/Attack ratio: {ratio:.1f}:1")
        if ratio < 1.5:
            print("  ⚠️  Too many attacks relative to normal. Consider increasing --users.")
        elif ratio > 10:
            print("  ⚠️  Too few attacks. Consider increasing AttackerUser weight.")
        else:
            print("  ✅ Ratio looks good for ML training!")

    print()


# ======================== MAIN ========================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MicroAPI Guard Dataset Generator")
    parser.add_argument("--users", "-u", type=int, default=DEFAULT_USERS,
                        help=f"Number of simulated users (default: {DEFAULT_USERS})")
    parser.add_argument("--spawn-rate", "-r", type=int, default=DEFAULT_SPAWN_RATE,
                        help=f"User spawn rate per second (default: {DEFAULT_SPAWN_RATE})")
    parser.add_argument("--time", "-t", type=str, default=DEFAULT_RUN_TIME,
                        help=f"Run time (default: {DEFAULT_RUN_TIME})")
    parser.add_argument("--no-clean", action="store_true",
                        help="Don't clean old JSONL file (append to existing)")
    args = parser.parse_args()

    print("=" * 60)
    print("     MicroAPI Guard - Dataset Generator")
    print("=" * 60)

    # Step 1: Clean old data
    if not args.no_clean:
        clean_old_data()

    # Step 2: Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    # Step 3: Run Locust
    run_locust(args.users, args.spawn_rate, args.time)

    # Step 4: Report statistics
    report_statistics()
