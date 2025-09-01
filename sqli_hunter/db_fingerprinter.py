# -*- coding: utf-8 -*-
"""
Database Fingerprinting Engine.

This module is responsible for identifying the backend database technology
of the target application.
"""
from playwright.async_api import BrowserContext, Error
import re

DB_FINGERPRINT_PAYLOADS = {
    "MySQL": [
        "' AND 1=1",
        "\" AND 1=1",
        "` AND 1=1",
        "AND 1=1"
    ],
    "PostgreSQL": [
        "' AND 1=1",
        "\" AND 1=1"
    ],
    "MSSQL": [
        "' AND 1=1",
        "\" AND 1=1"
    ],
    "Oracle": [
        "' AND 1=1",
        "\" AND 1=1"
    ]
}

DB_ERROR_PATTERNS = {
    "MySQL": "you have an error in your sql syntax|warning: mysql_fetch_array()|supplied argument is not a valid mysql result resource|unknown column '[^']+' in 'where clause'",
    "PostgreSQL": "postgresql query failed|unterminated quoted string|syntax error at or near|invalid input syntax for type",
    "MSSQL": "unclosed quotation mark after the character string|quoted string not properly terminated|invalid column name",
    "Oracle": "ora-00933: sql command not properly ended|ora-01756: quoted string not properly terminated|ora-00942: table or view does not exist|ora-01400: cannot insert null into"
}


class DbFingerprinter:
    """
    Detects the backend database of a target URL by analyzing error messages.
    """
    def __init__(self, browser_context: BrowserContext):
        self.context = browser_context

    async def detect_db(self, base_url: str) -> str | None:
        """
        Sends probes to the target and checks for database-specific error messages.

        :param base_url: The base URL of the target application.
        :return: The name of the detected database or None if no database is identified.
        """
        page = await self.context.new_page()
        try:
            for db_name, payloads in DB_FINGERPRINT_PAYLOADS.items():
                for payload in payloads:
                    target_url = f"{base_url.rstrip('/')}/?id=1{payload}"
                    try:
                        response = await page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
                        if response:
                            body = await response.text()
                            if re.search(DB_ERROR_PATTERNS[db_name], body, re.IGNORECASE):
                                print(f"[+] Database Detected: {db_name}")
                                return db_name
                    except Error:
                        continue
        finally:
            await page.close()

        print("[-] Database not detected.")
        return None
