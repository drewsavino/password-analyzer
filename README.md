# Password Analyzer

A real-time password strength checker with entropy analysis, crack-time estimation, and actionable feedback. Available as both a **browser-based UI** (`index.html`) and a **Python CLI** (`analyzer.py`).

---

## Features

- Real-time scoring (0–100) across 11 rules
- Shannon entropy calculation
- Offline crack-time estimation (assumes 10 billion guesses/sec)
- Actionable issues & suggestions
- Keyboard pattern, sequential character, and dictionary word detection
- Common password blocklist (200+ entries)
- CLI supports single password, file batch, interactive masked input, and JSON output

---

## Project Structure

```
├── index.html        # Standalone browser UI (no dependencies)
├── analyzer.py       # CLI entry point & core analysis logic
├── rules.py          # Scoring rules engine
├── requirements.txt  # Python dependencies (colorama, pytest)
└── wordlists/
    └── common_passwords.txt  # Optional external blocklist
```

---

## How It Works

### Scoring System

Every password is evaluated against 11 rules. The raw score is clamped to `[0, 100]`.

#### Positive Rules (earn points)

| Rule | Max Points | Logic |
|------|-----------|-------|
| Length | 25 | 0 pts if <8 chars; linear scale 8→15; full 25 at 16+ |
| Lowercase | 10 | Contains `[a-z]` |
| Uppercase | 10 | Contains `[A-Z]` |
| Digits | 10 | Contains `[0-9]` |
| Symbols | 10 | Contains any non-alphanumeric (including emoji) |
| Entropy bonus | 20 | `min(20, floor(entropy_bits / 80 * 20))` |
| No repeated chars | 5 | No 3+ consecutive identical characters (e.g. `aaa`) |
| No keyboard patterns | 5 | No keyboard walk ≥4 chars (e.g. `qwerty`, `1234`) |

#### Penalty Rules (deduct points)

| Rule | Penalty | Trigger |
|------|---------|---------|
| Common password | −20 | Exact match in blocklist |
| Dictionary word | −10 | Contains a common word ≥4 chars (e.g. `pass`, `admin`) |
| Sequential chars | −10 | 4+ ascending or descending chars (e.g. `abcd`, `9876`) |

#### Strength Labels

| Score | Label |
|-------|-------|
| 0–19 | Very Weak |
| 20–39 | Weak |
| 40–59 | Fair |
| 60–79 | Strong |
| 80–100 | Very Strong |

---

### Entropy Calculation

Entropy is calculated as:

```
entropy_bits = log2(charset_size) × length
```

The **charset size** is the number of possible characters based on which categories are present:

| Category | Adds |
|----------|------|
| Lowercase a–z | +26 |
| Uppercase A–Z | +26 |
| Digits 0–9 | +10 |
| Symbols / non-alphanumeric | +32 |

Higher entropy = more unpredictable = harder to crack.

---

### Crack Time Estimation

Assumes an **offline attack at 10 billion guesses/second** (a realistic GPU-based hash cracking rate). All math is done in log₂ space to prevent float overflow at high entropy values:

```
log2_seconds = entropy_bits − log2(10,000,000,000)
seconds = 2 ^ log2_seconds
```

Results are expressed as: *instantly → seconds → minutes → hours → days → years → centuries → practically forever*

---

### Pattern Detection

**Keyboard walks** — checked against common row patterns:
```
qwertyuiop, asdfghjkl, zxcvbnm, 1234567890, (and reversals)
```
Any substring ≥4 chars found in the lowercased password triggers a penalty.

**Sequential characters** — scans every 4-char window for ascending (`abcd`) or descending (`dcba`) runs by comparing adjacent char codes.

**Repeated characters** — regex `(.)\1{2,}` catches any character repeated 3+ times consecutively.

---

## Browser UI (`index.html`)

A fully self-contained single-file app — no build step, no dependencies, no server required. Open it directly in any browser.

**How it works:**
- The scoring logic from `rules.py` is re-implemented in vanilla JavaScript, keeping both in sync
- Analysis runs on every `input` event (keystroke) via `analyze(pw)`
- Results update the DOM in real time: score bar, strength label, entropy, crack time, character variety chips, issues list, and suggestions list
- A **Copy JSON Report** button copies the full analysis as structured JSON to the clipboard
- The 👁 toggle switches between masked and visible input

**Common password list** is embedded directly in the JS as a `Set` for O(1) lookups without any network requests.

---

## Python CLI (`analyzer.py`)

### Installation

```bash
pip install -r requirements.txt
```

### Usage

```bash
# Single password
python analyzer.py MyPassword123!

# Interactive masked input (password hidden while typing)
python analyzer.py --interactive

# Batch analyze a file (one password per line)
python analyzer.py --file passwords.txt

# JSON output (any mode)
python analyzer.py MyPassword123! --json
```

### Example Output

```
Password : MyPassword123!
Strength : Strong
Score    : [######################........] 74/100
Entropy  : 85.54 bits
Crack est: practically forever

Issues:
  [!] Contains common word 'pass'

Suggestions:
  --> Avoid common dictionary words embedded in your password
```

---

## Architecture Notes

### Python (`rules.py` + `analyzer.py`)

- Each rule is a standalone function returning a `RuleResult(points, issue, suggestion)`
- Rules are split into `POSITIVE_RULES` and `PENALTY_RULES` lists for clarity
- `PasswordAnalyzer.analyze()` iterates all rules, accumulates the score, and clamps to `[0, 100]`
- `colorama` is optional — the CLI degrades gracefully if it's not installed
- An optional external wordlist at `wordlists/common_passwords.txt` is loaded at import time into a `frozenset` for fast lookups; the embedded JS list is used as a fallback

### JavaScript (`index.html`)

- Mirrors the Python logic exactly: same rules, same thresholds, same scoring math
- Uses a `Set` for the common password blocklist (O(1) lookup)
- Crack time uses log₂ arithmetic to safely handle astronomical entropy values without `Infinity`
- The `render()` function is the single source of truth for all UI updates

---

## Dependencies

| Package | Use |
|---------|-----|
| `colorama` | Colored terminal output (optional) |
| `pytest` | Running tests |

---

## Security Notes

- Passwords are **never logged**. The CLI's debug helper only logs the first 8 chars of the SHA-256 hash
- The browser UI performs all analysis **locally** — no data is sent anywhere
- Crack time estimates assume offline attacks; online attacks (with rate limiting) would be orders of magnitude slower
