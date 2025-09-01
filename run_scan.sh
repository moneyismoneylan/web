#!/bin/bash

set -e

echo "--- Running SQLi Hunter Against New Target ---"

# Scan the specified URL with a crawl depth of 2
# A deeper crawl might be needed for a real site.
python main.py \
    --url https://radio.espressolab.com/ \
    --json-report scan_report.json \
    --depth 2 \
    --dump-db

echo "--- Scan Finished ---"
echo "Results saved to scan_report.json"

# Display the results if any vulnerabilities were found
if [ -s scan_report.json ] && [ "$(cat scan_report.json)" != "[]" ]; then
    echo "✅ VULNERABILITIES FOUND:"
    cat scan_report.json
else
    echo "[-] No vulnerabilities were found."
fi
