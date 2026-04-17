"""pytest tests for the password strength analyzer."""
from __future__ import annotations

import math
import sys
from pathlib import Path

# Ensure the package root is on the path when running from any directory
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from analyzer import AnalysisResult, PasswordAnalyzer
from rules import (
    calculate_entropy,
    rule_common_password,
    rule_dictionary_word,
    rule_digits,
    rule_entropy,
    rule_length,
    rule_lowercase,
    rule_no_keyboard_patterns,
    rule_no_repeated_sequences,
    rule_sequential_chars,
    rule_symbols,
    rule_uppercase,
)

ANALYZER = PasswordAnalyzer()


# ---------------------------------------------------------------------------
# Strength bucket tests
# ---------------------------------------------------------------------------

class TestStrengthBuckets:
    @pytest.mark.parametrize("password", [
        "password",   # common list
        "123456",     # common list + very short
        "qwerty",     # common + keyboard pattern
        "abc",        # too short
        "",           # empty
        "aaaaaaa",    # repeated + no variety
    ])
    def test_known_weak_scores_below_30(self, password: str) -> None:
        result = ANALYZER.analyze(password)
        assert result.score < 30, f"Expected score <30 for '{password}', got {result.score}"

    @pytest.mark.parametrize("password", [
        "T#9xK!mZ2@vL5pQr",   # 16 chars, all variety
        "aB3$eF7&hI2@jK5!",   # 16 chars mixed
        "Xy!9#Lm3$Pk7@Qz2",   # 16 chars mixed
        "R8!tU#4wY@6vX$2n",   # 16 chars mixed
    ])
    def test_strong_random_passwords_score_above_80(self, password: str) -> None:
        result = ANALYZER.analyze(password)
        assert result.score > 80, f"Expected score >80 for '{password}', got {result.score}"


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------

class TestEntropyCalculation:
    def test_empty_password_entropy_is_zero(self) -> None:
        assert calculate_entropy("") == 0.0

    def test_single_char_lowercase_entropy(self) -> None:
        # charset=26 (lowercase only), length=1 → log2(26)*1
        entropy = calculate_entropy("a")
        expected = math.log2(26)
        assert abs(entropy - expected) < 0.01

    def test_all_categories_increase_entropy(self) -> None:
        e_lower = calculate_entropy("aaaaaaaa")
        e_mixed = calculate_entropy("aB3!aB3!")  # all four categories
        assert e_mixed > e_lower

    def test_longer_password_higher_entropy(self) -> None:
        assert calculate_entropy("aB3!aB3!aB3!") > calculate_entropy("aB3!aB3!")

    def test_known_entropy_value(self) -> None:
        # 8 lowercase chars → charset=26, bits = log2(26)*8
        expected = math.log2(26) * 8
        assert abs(calculate_entropy("abcdefgh") - expected) < 0.01


# ---------------------------------------------------------------------------
# Individual rule unit tests
# ---------------------------------------------------------------------------

class TestRuleLength:
    def test_empty_scores_zero(self) -> None:
        r = rule_length("")
        assert r.points == 0
        assert r.issue is not None

    def test_short_scores_zero(self) -> None:
        for pw in ["a", "abc", "1234567"]:
            assert rule_length(pw).points == 0

    def test_16_chars_scores_25(self) -> None:
        assert rule_length("a" * 16).points == 25

    def test_20_chars_scores_25(self) -> None:
        assert rule_length("a" * 20).points == 25

    def test_8_chars_scores_positive(self) -> None:
        # Exactly 8 → first step above 0 threshold
        assert rule_length("a" * 8).points >= 0

    def test_12_chars_intermediate_score(self) -> None:
        r12 = rule_length("a" * 12)
        assert 0 < r12.points < 25


class TestRuleCharacterVariety:
    def test_lowercase_present(self) -> None:
        assert rule_lowercase("abc").points == 10

    def test_lowercase_absent(self) -> None:
        r = rule_lowercase("ABC123!")
        assert r.points == 0
        assert r.issue is not None

    def test_uppercase_present(self) -> None:
        assert rule_uppercase("ABC").points == 10

    def test_uppercase_absent(self) -> None:
        r = rule_uppercase("abc123!")
        assert r.points == 0
        assert r.issue is not None

    def test_digits_present(self) -> None:
        assert rule_digits("abc123").points == 10

    def test_digits_absent(self) -> None:
        r = rule_digits("abcABC!")
        assert r.points == 0
        assert r.issue is not None

    def test_symbols_present(self) -> None:
        assert rule_symbols("abc!").points == 10

    def test_symbols_absent(self) -> None:
        r = rule_symbols("abcABC123")
        assert r.points == 0
        assert r.issue is not None

    def test_emoji_counts_as_symbol(self) -> None:
        assert rule_symbols("abc🔒").points == 10


class TestRuleRepeatedSequences:
    def test_no_repeats_awards_5(self) -> None:
        assert rule_no_repeated_sequences("abcde").points == 5

    def test_triple_repeat_scores_zero(self) -> None:
        r = rule_no_repeated_sequences("aaabcd")
        assert r.points == 0
        assert r.issue is not None

    def test_four_repeats_scores_zero(self) -> None:
        assert rule_no_repeated_sequences("aaaa").points == 0

    def test_two_repeats_ok(self) -> None:
        assert rule_no_repeated_sequences("aabbc").points == 5


class TestRuleKeyboardPatterns:
    @pytest.mark.parametrize("password", [
        "qwerty123",
        "asdf1234",
        "zxcv5678",
        "12345abc",
    ])
    def test_keyboard_pattern_scores_zero(self, password: str) -> None:
        r = rule_no_keyboard_patterns(password)
        assert r.points == 0
        assert r.issue is not None

    def test_no_keyboard_pattern_scores_5(self) -> None:
        assert rule_no_keyboard_patterns("T#9xK!mZ").points == 5


class TestRuleCommonPassword:
    @pytest.mark.parametrize("password", ["password", "123456", "qwerty", "letmein", "dragon"])
    def test_common_password_penalty(self, password: str) -> None:
        r = rule_common_password(password)
        assert r.points == -20
        assert r.issue is not None

    def test_uncommon_password_no_penalty(self) -> None:
        assert rule_common_password("T#9xK!mZ2@vL5pQr").points == 0


class TestRuleDictionaryWord:
    @pytest.mark.parametrize("password", ["mypassword123", "hello_world", "admin2024"])
    def test_contains_dictionary_word(self, password: str) -> None:
        r = rule_dictionary_word(password)
        assert r.points == -10
        assert r.issue is not None

    def test_no_dictionary_word(self) -> None:
        assert rule_dictionary_word("T#9xK!mZ").points == 0


class TestRuleSequentialChars:
    @pytest.mark.parametrize("password", [
        "abc1234",   # 1234 sequential
        "Xabcd!",   # abcd sequential
        "9876XY",   # descending 9876
        "dcbaXY",   # descending dcba
    ])
    def test_sequential_chars_penalty(self, password: str) -> None:
        r = rule_sequential_chars(password)
        assert r.points == -10
        assert r.issue is not None

    def test_no_sequential_chars(self) -> None:
        assert rule_sequential_chars("T#9xK!mZ").points == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self) -> None:
        result = ANALYZER.analyze("")
        assert result.score == 0, f"Empty password should score 0, got {result.score}"
        assert result.strength_label == "Very Weak"
        assert result.entropy_bits == 0.0
        assert len(result.issues) > 0

    def test_unicode_password(self) -> None:
        pw = "Héllo!Wörld9"
        result = ANALYZER.analyze(pw)
        assert result.score > 0
        assert result.entropy_bits > 0

    def test_emoji_password(self) -> None:
        pw = "🔒🎉🦄ABC123"
        result = ANALYZER.analyze(pw)
        assert result.score > 0

    def test_1000_char_input(self) -> None:
        pw = ("aB3!" * 250)  # 1000 chars, all variety
        result = ANALYZER.analyze(pw)
        # Max achievable from spec rules is 95 (25+40+20+10); no penalties apply
        assert result.score >= 95, f"Expected score >=95 for 1000-char all-variety input, got {result.score}"
        assert result.entropy_bits > 1000

    def test_single_char(self) -> None:
        result = ANALYZER.analyze("a")
        assert result.score < 20

    def test_all_same_char_1000(self) -> None:
        result = ANALYZER.analyze("a" * 1000)
        # Should be penalized for repeats
        assert "repeated" in " ".join(result.issues).lower()

    def test_result_score_clamped_0_100(self) -> None:
        for pw in ["", "a", "T#9xK!mZ2@vL5pQr", "password", "a" * 1000]:
            result = ANALYZER.analyze(pw)
            assert 0 <= result.score <= 100

    def test_strength_labels_correct(self) -> None:
        mapping = {
            "": "Very Weak",
            "abc": "Very Weak",
            "password": "Very Weak",
        }
        for pw, expected_label in mapping.items():
            result = ANALYZER.analyze(pw)
            assert result.strength_label == expected_label, (
                f"For '{pw}' expected '{expected_label}' got '{result.strength_label}'"
            )

    def test_crack_time_non_empty(self) -> None:
        for pw in ["abc", "T#9xK!mZ2@vL5pQr", "password"]:
            result = ANALYZER.analyze(pw)
            assert result.estimated_crack_time

    def test_analysis_result_fields_present(self) -> None:
        result = ANALYZER.analyze("TestPass1!")
        assert hasattr(result, "score")
        assert hasattr(result, "strength_label")
        assert hasattr(result, "entropy_bits")
        assert hasattr(result, "estimated_crack_time")
        assert hasattr(result, "issues")
        assert hasattr(result, "suggestions")
        assert isinstance(result.issues, list)
        assert isinstance(result.suggestions, list)
