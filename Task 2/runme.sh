#!/bin/bash
set -e

# Step 1: Create venv if not exists
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# Step 2: Activate venv
source venv/bin/activate

# Step 3: Upgrade pip and install dependencies
echo "[*] Installing dependencies..."
pip install --upgrade pip > /dev/null
pip install requests beautifulsoup4 lxml flask > /dev/null

# Step 4: Start vulnerable test app in background
echo "[*] Starting local vulnerable app (test_app.py) on http://127.0.0.1:5000 ..."
python3 test_app.py > app.log 2>&1 &
APP_PID=$!

# Give the app a moment to start
sleep 2

# Step 5: Run scanner
echo "[*] Running vulnerability scanner..."
python3 simple_vuln_scanner.py

# Step 6: Kill the test app
echo "[*] Stopping local vulnerable app..."
kill $APP_PID

# Step 7: Open results in VS Code
if command -v code > /dev/null; then
    echo "[*] Opening scan_report.json in VS Code..."
    code scan_report.json
else
    echo "[!] VS Code not found. Please open scan_report.json manually."
fi

echo "[*] Done! Results saved in scan_report.json"
