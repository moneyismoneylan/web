#!/bin/bash

set -e
echo "--- Building Benchmark Docker Image ---"
docker build -t sqli-hunter-benchmark ./benchmark

echo "--- Starting Benchmark Server ---"
CONTAINER_ID=$(docker run -d -p 5000:5000 sqli-hunter-benchmark)

# Give the server a moment to start
sleep 5

echo "--- Running SQLi Hunter Against Benchmark ---"
python main.py --url http://localhost:5000 --json-report benchmark_report.json --no-crawl

echo "--- Stopping Benchmark Server ---"
docker stop $CONTAINER_ID
docker rm $CONTAINER_ID

echo "--- Verifying Results ---"
# Check if the 3 known vulnerabilities were found
# 1. GET /user?id=...
# 2. POST /search with form
# 3. POST /api/user with JSON
# This is a simplified check. A more robust check would parse the JSON properly.
VULN_COUNT=$(grep -c 'vulnerable_points' benchmark_report.json || echo "0") # A basic check

# A better check would be more specific
USER_VULN=$(grep -c '/user' benchmark_report.json || echo "0")
SEARCH_VULN=$(grep -c '/search' benchmark_report.json || echo "0")
API_VULN=$(grep -c '/api/user' benchmark_report.json || echo "0")

TOTAL_FOUND=$((USER_VULN + SEARCH_VULN + API_VULN))

if [ "$TOTAL_FOUND" -ge 3 ]; then
    echo "✅ BENCHMARK PASSED: Found all 3 vulnerabilities."
    exit 0
else
    echo "❌ BENCHMARK FAILED: Found $TOTAL_FOUND out of 3 vulnerabilities."
    exit 1
fi
