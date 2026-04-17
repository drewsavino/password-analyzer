"""Scoring rules and checks for password strength analysis."""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent / "wordlists" / "common_passwords.txt"

# Keyboard row patterns used for pattern detection
_KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qwerty", "asdf", "zxcv", "wasd",
    "1234567890", "0987654321",
]

# Short common dictionary words to flag (≥4 chars checked against password)
_COMMON_WORDS = [
    "pass", "word", "love", "hate", "test", "user", "admin", "root",
    "login", "hello", "welcome", "dragon", "master", "monkey", "shadow",
    "sunshine", "princess", "football", "baseball", "soccer", "hockey",
    "batman", "superman", "michael", "jessica", "charlie", "thomas",
]


@dataclass
class RuleResult:
    points: int
    issue: str | None = None
    suggestion: str | None = None


def _load_common_passwords() -> frozenset[str]:
    if not WORDLIST_PATH.exists():
        return frozenset()
    return frozenset(line.strip().lower() for line in WORDLIST_PATH.read_text(encoding="utf-8").splitlines() if line.strip())


_COMMON_PASSWORDS: frozenset[str] = _load_common_passwords()


def _charset_size(password: str) -> int:
    """Return the effective charset size based on character categories present."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    # Symbols: anything not alphanumeric (includes unicode/emoji)
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 32
    return max(size, 1)


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy estimate: log2(charset_size ^ length)."""
    length = len(password)
    if length == 0:
        return 0.0
    charset = _charset_size(password)
    return math.log2(charset) * length


# ---------------------------------------------------------------------------
# Individual rule functions — each returns a RuleResult
# ---------------------------------------------------------------------------

def rule_length(password: str) -> RuleResult:
    """0 pts if <8, scales to 25 pts at 16+ chars."""
    n = len(password)
    if n == 0:
        return RuleResult(0, "Password is empty", "Enter a non-empty password")
    if n < 8:
        return RuleResult(
            0,
            f"Too short ({n} chars, minimum 8)",
            "Use at least 8 characters; 16+ is recommended",
        )
    if n >= 16:
        return RuleResult(25)
    # Linear scale 8→0 pts to 15→24 pts
    pts = int((n - 8) / (16 - 8) * 25)
    return RuleResult(pts, None, "Increase length to 16+ characters for maximum points" if n < 16 else None)


def rule_lowercase(password: str) -> RuleResult:
    if re.search(r"[a-z]", password):
        return RuleResult(10)
    return RuleResult(0, "No lowercase letters", "Add lowercase letters (a–z)")


def rule_uppercase(password: str) -> RuleResult:
    if re.search(r"[A-Z]", password):
        return RuleResult(10)
    return RuleResult(0, "No uppercase letters", "Add uppercase letters (A–Z)")


def rule_digits(password: str) -> RuleResult:
    if re.search(r"[0-9]", password):
        return RuleResult(10)
    return RuleResult(0, "No digits", "Add digits (0–9)")


def rule_symbols(password: str) -> RuleResult:
    if re.search(r"[^a-zA-Z0-9]", password):
        return RuleResult(10)
    return RuleResult(0, "No symbols or special characters", "Add symbols (!, @, #, $, …) or emoji")


def rule_entropy(password: str) -> RuleResult:
    """Award up to 20 pts based on entropy bits (capped at 80 bits → 20 pts)."""
    bits = calculate_entropy(password)
    pts = min(20, int(bits / 80 * 20))
    return RuleResult(pts)


def rule_no_repeated_sequences(password: str) -> RuleResult:
    """+5 if no 3+ consecutive identical characters (requires length >= 3 to earn bonus)."""
    if len(password) < 3:
        return RuleResult(0)
    if re.search(r"(.)\1{2,}", password):
        return RuleResult(0, "Contains repeated characters (e.g. 'aaa')", "Avoid repeating the same character 3+ times in a row")
    return RuleResult(5)


def rule_no_keyboard_patterns(password: str) -> RuleResult:
    """+ 5 if no keyboard walk patterns of length ≥4 (requires length >= 4 to earn bonus)."""
    if len(password) < 4:
        return RuleResult(0)
    lower = password.lower()
    for pattern in _KEYBOARD_PATTERNS:
        for length in range(4, len(pattern) + 1):
            for start in range(len(pattern) - length + 1):
                chunk = pattern[start:start + length]
                if chunk in lower:
                    return RuleResult(
                        0,
                        f"Contains keyboard pattern '{chunk}'",
                        "Avoid keyboard sequences like 'qwerty' or '1234'",
                    )
    return RuleResult(5)


def rule_common_password(password: str) -> RuleResult:
    """-20 if the password is in the common passwords list."""
    if password.lower() in _COMMON_PASSWORDS:
        return RuleResult(-20, "Password is in the common passwords list", "Choose a unique password not found in breach databases")
    return RuleResult(0)


def rule_dictionary_word(password: str) -> RuleResult:
    """-10 if the password contains a common dictionary word ≥4 chars."""
    lower = password.lower()
    for word in _COMMON_WORDS:
        if len(word) >= 4 and word in lower:
            return RuleResult(-10, f"Contains common word '{word}'", "Avoid common dictionary words embedded in your password")
    return RuleResult(0)


def rule_sequential_chars(password: str) -> RuleResult:
    """-10 if 4+ sequential characters (abcd, 1234, dcba, 9876)."""
    lower = password.lower()
    for i in range(len(lower) - 3):
        chunk = lower[i:i + 4]
        # Check ascending sequence
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(3)):
            return RuleResult(-10, f"Contains sequential characters '{chunk}'", "Avoid sequential runs like 'abcd' or '1234'")
        # Check descending sequence
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(3)):
            return RuleResult(-10, f"Contains descending sequence '{chunk}'", "Avoid sequential runs like 'dcba' or '9876'")
    return RuleResult(0)


# Ordered list of all rules; penalties are applied after positives
POSITIVE_RULES = [
    rule_length,
    rule_lowercase,
    rule_uppercase,
    rule_digits,
    rule_symbols,
    rule_entropy,
    rule_no_repeated_sequences,
    rule_no_keyboard_patterns,
]

PENALTY_RULES = [
    rule_common_password,
    rule_dictionary_word,
    rule_sequential_chars,
]

ALL_RULES = POSITIVE_RULES + PENALTY_RULES
