# -*- coding: utf-8 -*-
"""Payload Manager.

This module loads SQL injection payloads and error patterns from an external
configuration file via the bootstrap loader. Using configuration files allows
the payload database to be updated without modifying source code."""
from __future__ import annotations

import re
from sqli_hunter.bootstrap import load_config


_CONFIG = load_config("payload_config")

# A comprehensive list of common SQL error messages. Used to identify
# potential error-based SQLi vulnerabilities.
SQL_ERROR_PATTERNS = _CONFIG.get("SQL_ERROR_PATTERNS", [])

# Simple payloads designed to trigger database errors. Each tuple is
# (payload_string, family_tag)
ERROR_BASED_PAYLOADS = [tuple(p) for p in _CONFIG.get("ERROR_BASED_PAYLOADS", [])]

# Payloads for Out-of-Band (OOB) SQLi.
OOB_PAYLOADS = _CONFIG.get("OOB_PAYLOADS", [])

# Payloads for Error-Based data extraction (base64 encoded).
EXTRACTION_PAYLOADS_B64 = _CONFIG.get("EXTRACTION_PAYLOADS_B64", {})

# Specific queries to be used with extraction payloads (base64 encoded).
EXTRACTION_QUERIES_B64 = _CONFIG.get("EXTRACTION_QUERIES_B64", {})


# Legacy constant retained for backward compatibility.
MSSQL_ERROR_BASED_PAYLOADS_B64 = _CONFIG.get("MSSQL_ERROR_BASED_PAYLOADS_B64", [])
