# -*- coding: utf-8 -*-
"""
WAF Evasion Engine (Tamper Scripts).

This module contains a collection of functions to modify SQLi payloads
in order to bypass web application firewalls.
"""
import random
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

# A dictionary to map tamper script names to their respective functions.
# This makes the tamper engine easily extensible.
TAMPER_FUNCTIONS = {
    'space2comment': space_to_comment,
    'randomcase': random_case,
    'urlencode': plus_url_encode,
    'chardoubleencode': char_double_encode,
    'equaltolike': equal_to_like,
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
    "Cloudflare": ["space2comment", "randomcase"],
    "Sucuri": ["urlencode", "space2comment"],
    "Akamai": ["randomcase"],
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
