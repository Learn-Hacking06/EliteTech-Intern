import os
import hashlib
import json
from pathlib import Path
import argparse

# Function to calculate hash of a file
def calculate_hash(file_path, algorithm="sha256", chunk_size=8192):
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()

# Scan a directory and create baseline data
def create_baseline(directory, baseline_file, algorithm="sha256"):
    data = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, directory)
            try:
                data[rel_path] = calculate_hash(full_path, algorithm)
            except Exception as e:
                print(f"Skipping {file}: {e}")
    with open(baseline_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Baseline created with {len(data)} files → {baseline_file}")

# Compare current state with baseline
def check_integrity(directory, baseline_file, algorithm="sha256"):
    with open(baseline_file, "r") as f:
        baseline = json.load(f)

    current = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, directory)
            try:
                current[rel_path] = calculate_hash(full_path, algorithm)
            except:
                continue

    added = [f for f in current if f not in baseline]
    removed = [f for f in baseline if f not in current]
    modified = [f for f in current if f in baseline and current[f] != baseline[f]]

    print("\n=== File Integrity Report ===")
    print(f"Added: {added}")
    print(f"Removed: {removed}")
    print(f"Modified: {modified}")
    print("=============================")

# Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor")
    parser.add_argument("mode", choices=["init", "check"],
                        help="init = create baseline, check = verify integrity")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("--baseline", default="baseline.json",
                        help="Baseline file path (default: baseline.json)")
    parser.add_argument("--algo", default="sha256",
                        help="Hash algorithm (default: sha256)")

    args = parser.parse_args()

    if args.mode == "init":
        create_baseline(args.directory, args.baseline, args.algo)
    elif args.mode == "check":
        check_integrity(args.directory, args.baseline, args.algo)
