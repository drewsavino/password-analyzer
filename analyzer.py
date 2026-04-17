#!/usr/bin/env python3
"""Password strength analyzer — CLI entry point and core analysis logic."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import json
import math
import sys
from dataclasses import asdict, dataclass, field

# Ensure UTF-8 output on Windows where the default console encoding may be cp1252
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

from rules import (
    ALL_RULES,
    PENALTY_RULES,
    POSITIVE_RULES,
    calculate_entropy,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    score: int
    strength_label: str
    entropy_bits: float
    estimated_crack_time: str
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

_GUESSES_PER_SECOND = 1e10  # offline attack assumption


_LOG2_GUESSES_PER_SEC = math.log2(1e10)  # ≈ 33.22


def _crack_time(entropy_bits: float) -> str:
    """Convert entropy to a human-readable crack-time string.

    Works entirely in log2 space to avoid float overflow for huge entropy values.
    """
    if entropy_bits <= 0:
        return "instantly"
    log2_secs = entropy_bits - _LOG2_GUESSES_PER_SEC
    if log2_secs < 0:
        return "instantly"

    # float max ≈ 2^1023; anything larger is "practically forever"
    if log2_secs > 1020:
        return "practically forever"

    def _exceeds(threshold_secs: float) -> bool:
        return log2_secs > math.log2(threshold_secs)

    if not _exceeds(1):
        return "instantly"
    secs = 2.0 ** log2_secs
    if not _exceeds(60):
        return f"{secs:.1f} seconds"
    if not _exceeds(3600):
        return f"{secs / 60:.1f} minutes"
    if not _exceeds(86400):
        return f"{secs / 3600:.1f} hours"
    if not _exceeds(86400 * 365):
        return f"{secs / 86400:.1f} days"
    if not _exceeds(86400 * 365 * 100):
        return f"{secs / (86400 * 365):.1f} years"
    if not _exceeds(86400 * 365 * 100_000):
        return f"{secs / (86400 * 365 * 100):.1f} centuries"
    return "practically forever"


def _strength_label(score: int) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very Strong"


def _log_hash_prefix(password: str) -> str:
    """Return first 8 chars of SHA-256 for debug logging — never the password itself."""
    return hashlib.sha256(password.encode()).hexdigest()[:8]


class PasswordAnalyzer:
    def analyze(self, password: str) -> AnalysisResult:
        entropy = calculate_entropy(password)
        raw_score = 0
        issues: list[str] = []
        suggestions: list[str] = []

        for rule_fn in ALL_RULES:
            result = rule_fn(password)
            raw_score += result.points
            if result.issue:
                issues.append(result.issue)
            if result.suggestion:
                suggestions.append(result.suggestion)

        score = max(0, min(100, raw_score))
        return AnalysisResult(
            score=score,
            strength_label=_strength_label(score),
            entropy_bits=round(entropy, 2),
            estimated_crack_time=_crack_time(entropy),
            issues=issues,
            suggestions=suggestions,
        )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _color_for_score(score: int) -> str:
    if not _COLOR:
        return ""
    if score < 40:
        return Fore.RED
    if score < 60:
        return Fore.YELLOW
    return Fore.GREEN


def _reset() -> str:
    return Style.RESET_ALL if _COLOR else ""


def _score_bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    bar = "#" * filled + "." * (width - filled)
    color = _color_for_score(score)
    return f"{color}[{bar}]{_reset()} {score}/100"


def format_result(password_display: str, result: AnalysisResult) -> str:
    color = _color_for_score(result.score)
    lines = [
        f"\nPassword : {password_display}",
        f"Strength : {color}{result.strength_label}{_reset()}",
        f"Score    : {_score_bar(result.score)}",
        f"Entropy  : {result.entropy_bits:.2f} bits",
        f"Crack est: {result.estimated_crack_time}",
    ]
    if result.issues:
        lines.append("\nIssues:")
        for issue in result.issues:
            prefix = f"  {Fore.RED}[!]{_reset()}" if _COLOR else "  [!]"
            lines.append(f"{prefix} {issue}")
    if result.suggestions:
        lines.append("\nSuggestions:")
        for tip in result.suggestions:
            prefix = f"  {Fore.CYAN}-->{_reset()}" if _COLOR else "  -->"
            lines.append(f"{prefix} {tip}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _analyze_and_print(password: str, as_json: bool, mask: bool = False) -> None:
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password)
    display = "****" if mask else password
    if as_json:
        data = asdict(result)
        data["password_display"] = display
        print(json.dumps(data, indent=2))
    else:
        print(format_result(display, result))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="Analyze password strength",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("password", nargs="?", help="Password to analyze")
    group.add_argument("--file", "-f", metavar="FILE", help="File with one password per line")
    group.add_argument("--interactive", "-i", action="store_true", help="Prompt with masked input")
    parser.add_argument("--json", "-j", action="store_true", dest="as_json", help="Output JSON")
    args = parser.parse_args()

    if args.interactive:
        while True:
            try:
                pw = getpass.getpass("Enter password (Ctrl-C to quit): ")
            except (KeyboardInterrupt, EOFError):
                print("\nBye.")
                break
            if not pw:
                print("(empty — skipping)")
                continue
            _analyze_and_print(pw, args.as_json, mask=True)
    elif args.file:
        try:
            lines = open(args.file, encoding="utf-8").read().splitlines()
        except OSError as exc:
            sys.exit(f"Error reading file: {exc}")
        results = []
        for pw in lines:
            if not pw:
                continue
            analyzer = PasswordAnalyzer()
            result = analyzer.analyze(pw)
            if args.as_json:
                data = asdict(result)
                data["password"] = pw
                results.append(data)
            else:
                print(format_result(pw, result))
                print("-" * 50)
        if args.as_json:
            print(json.dumps(results, indent=2))
    elif args.password:
        _analyze_and_print(args.password, args.as_json)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
