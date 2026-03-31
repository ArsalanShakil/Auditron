"""Text normalization pipeline to defeat evasion techniques.

Handles Unicode homoglyphs, zero-width characters, whitespace variants,
base64/hex/URL encoding, and shell command substitution detection.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote as url_unquote

# Cyrillic/Greek lookalikes → Latin equivalents
_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у (visually close to y)
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0501": "d",  # Cyrillic ԁ
    "\u051b": "q",  # Cyrillic ԛ
    "\u0261": "g",  # Latin script ɡ
    "\u03bf": "o",  # Greek omicron ο
    "\u03b1": "a",  # Greek alpha α
    "\u03b5": "e",  # Greek epsilon ε
    "\u03b9": "i",  # Greek iota ι
    "\u03ba": "k",  # Greek kappa κ
    "\u03bd": "v",  # Greek nu ν (visually close)
    "\u03c1": "p",  # Greek rho ρ
    "\u03c4": "t",  # Greek tau τ
    "\u0391": "A",  # Greek Alpha Α
    "\u0392": "B",  # Greek Beta Β
    "\u0395": "E",  # Greek Epsilon Ε
    "\u0397": "H",  # Greek Eta Η
    "\u0399": "I",  # Greek Iota Ι
    "\u039a": "K",  # Greek Kappa Κ
    "\u039c": "M",  # Greek Mu Μ
    "\u039d": "N",  # Greek Nu Ν
    "\u039f": "O",  # Greek Omicron Ο
    "\u03a1": "P",  # Greek Rho Ρ
    "\u03a4": "T",  # Greek Tau Τ
    "\u03a7": "X",  # Greek Chi Χ
    "\u03a5": "Y",  # Greek Upsilon Υ
    "\u0417": "3",  # Cyrillic З (looks like 3)
}

# Build translation table for confusables
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# Zero-width and format characters to strip
_ZERO_WIDTH_CHARS = frozenset(
    "\u200b\u200c\u200d\ufeff\u2060\u00ad\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
)

# Base64 detection: 8+ chars of base64 alphabet, optional padding
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")

# Hex escape patterns: \x41\x42 or 0x41 0x42
_HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")
_HEX_SPACE_PATTERN = re.compile(r"(?:0x[0-9a-fA-F]{2}\s*){2,}")

# URL encoding: %41%42
_URL_ENCODE_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")

# Shell substitution patterns
_SHELL_SUB_PATTERN = re.compile(r"\$\([^)]+\)|`[^`]+`|\$\{[^}]+\}|<\([^)]+\)")

# Tool name alias map
_TOOL_ALIASES: dict[str, str] = {
    "sh": "bash",
    "zsh": "bash",
    "ksh": "bash",
    "csh": "bash",
    "dash": "bash",
    "fish": "bash",
    "cmd": "shell",
    "cmd.exe": "shell",
    "powershell": "shell",
    "pwsh": "shell",
    "python3": "python",
    "python3.10": "python",
    "python3.11": "python",
    "python3.12": "python",
    "python3.13": "python",
    "node": "node",
    "nodejs": "node",
}

# Suffixes to strip from tool names
_TOOL_SUFFIXES = ("_wrapper", "_tool", "_exec", "_runner", "_cmd")


@dataclass
class NormalizedText:
    """Holds both original and normalized forms of text."""

    original: str
    normalized: str
    flags: set[str] = field(default_factory=set)


class TextNormalizer:
    """Multi-stage text normalization pipeline."""

    def normalize(self, text: str) -> NormalizedText:
        """Run all normalization stages. Returns NormalizedText with flags."""
        if not text:
            return NormalizedText(original="", normalized="", flags=set())

        flags: set[str] = set()
        original = text

        # Stage 1: Unicode NFKC normalization
        text = unicodedata.normalize("NFKC", text)

        # Stage 2: Confusable character replacement
        before = text
        text = text.translate(_CONFUSABLE_TABLE)
        if text != before:
            flags.add("unicode_homoglyph")

        # Stage 3: Zero-width and format character removal
        before = text
        # Remove known zero-width chars
        text = "".join(c for c in text if c not in _ZERO_WIDTH_CHARS)
        # Remove remaining Unicode format characters (category Cf)
        text = "".join(c for c in text if unicodedata.category(c) != "Cf")
        if text != before:
            flags.add("zero_width_stripped")

        # Stage 4: Whitespace normalization
        text = re.sub(r"[\s\u00a0\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+", " ", text)
        text = text.strip()

        # Stage 5: Encoding expansion (append decoded forms)
        decoded_parts: list[str] = []

        # Base64 detection
        for match in _BASE64_PATTERN.finditer(text):
            chunk = match.group(0)
            decoded = _try_base64_decode(chunk)
            if decoded:
                decoded_parts.append(decoded)
                flags.add("base64_decoded")

        # Hex escape detection (\x72\x6d)
        for match in _HEX_ESCAPE_PATTERN.finditer(text):
            decoded = _decode_hex_escapes(match.group(0))
            if decoded:
                decoded_parts.append(decoded)
                flags.add("hex_decoded")

        # Hex space detection (0x72 0x6d)
        for match in _HEX_SPACE_PATTERN.finditer(text):
            decoded = _decode_hex_space(match.group(0))
            if decoded:
                decoded_parts.append(decoded)
                flags.add("hex_decoded")

        # URL encoding detection (%72%6d)
        for match in _URL_ENCODE_PATTERN.finditer(text):
            try:
                decoded = url_unquote(match.group(0))
                if decoded != match.group(0):
                    decoded_parts.append(decoded)
                    flags.add("url_decoded")
            except Exception:
                pass

        if decoded_parts:
            text = text + " " + " ".join(decoded_parts)

        # Stage 6: Shell substitution detection
        if _SHELL_SUB_PATTERN.search(text):
            flags.add("shell_substitution")

        return NormalizedText(original=original, normalized=text, flags=flags)


def normalize_tool_name(name: str) -> str:
    """Normalize a tool name to canonical form.

    Lowercases, strips path prefix, strips common suffixes, maps aliases.
    """
    if not name:
        return name

    # Lowercase
    result = name.lower().strip()

    # Strip path prefix (/bin/bash -> bash, /usr/bin/env -> env)
    if "/" in result:
        result = result.rsplit("/", 1)[-1]

    # Strip common suffixes
    for suffix in _TOOL_SUFFIXES:
        if result.endswith(suffix) and len(result) > len(suffix):
            result = result[: -len(suffix)]
            break

    # Apply alias mapping
    result = _TOOL_ALIASES.get(result, result)

    return result


# Parameter keys that commonly contain executable content
PARAM_KEYS = ["command", "cmd", "script", "code", "args", "input", "query", "body", "expression"]


def extract_raw_input(parameters: dict | None) -> str:
    """Extract executable content from parameters by checking multiple key names."""
    if not parameters:
        return ""
    parts: list[str] = []
    for key in PARAM_KEYS:
        val = parameters.get(key)
        if val and isinstance(val, str):
            parts.append(val)
    return " ".join(parts) if parts else ""


def _try_base64_decode(chunk: str) -> str | None:
    """Try to decode a base64 chunk. Returns decoded string or None."""
    # Pad if necessary
    padded = chunk + "=" * (4 - len(chunk) % 4) if len(chunk) % 4 else chunk
    try:
        decoded = base64.b64decode(padded)
        # Check if it's valid UTF-8 text (not random binary)
        text = decoded.decode("utf-8")
        # Only return if it contains printable content
        if text.isprintable() or any(c.isalpha() for c in text):
            return text
    except Exception:
        pass
    return None


def _decode_hex_escapes(text: str) -> str | None:
    """Decode \\x41\\x42 style hex escapes."""
    try:
        # Extract hex bytes
        hex_bytes = re.findall(r"\\x([0-9a-fA-F]{2})", text)
        if hex_bytes:
            decoded = bytes(int(h, 16) for h in hex_bytes).decode("utf-8", errors="ignore")
            if decoded and any(c.isalpha() for c in decoded):
                return decoded
    except Exception:
        pass
    return None


def _decode_hex_space(text: str) -> str | None:
    """Decode 0x41 0x42 style hex sequences."""
    try:
        hex_bytes = re.findall(r"0x([0-9a-fA-F]{2})", text)
        if hex_bytes:
            decoded = bytes(int(h, 16) for h in hex_bytes).decode("utf-8", errors="ignore")
            if decoded and any(c.isalpha() for c in decoded):
                return decoded
    except Exception:
        pass
    return None
