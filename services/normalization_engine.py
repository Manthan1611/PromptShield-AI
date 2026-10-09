"""Security-oriented input normalization and encoding inspection."""

import base64
import binascii
import codecs
import html
import re
import unicodedata
from urllib.parse import unquote

ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u206f\ufeff]")
BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
UNICODE_ESC = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}")
URL_ESC = re.compile(r"%[0-9A-Fa-f]{2}")


class NormalizationEngine:
    def inspect(self, text):
        original = text or ""
        normalized = unicodedata.normalize("NFKC", original)
        transformations = []
        detections = []
        suspicious = []
        risk = 0

        def add(t, fragment, decoded, confidence, reason, points=0):
            nonlocal risk
            transformations.append({"type": t, "original_fragment": fragment, "decoded_fragment": decoded,
                                    "confidence": confidence, "reason": reason})
            risk += points

        if normalized != original:
            add("unicode_normalization", original, normalized, 0.99, "NFKC normalization changed the input", 4)

        cleaned = re.sub(r"[ \t\r\n]+", " ", normalized).strip()
        if cleaned != normalized:
            add("whitespace_normalization", normalized, cleaned, 0.98, "Collapsed repeated whitespace", 1)
        normalized = cleaned

        zw = ZERO_WIDTH.findall(normalized)
        if zw:
            fragment = "".join(zw)
            visible = ZERO_WIDTH.sub("", normalized)
            add("zero_width", fragment, "", 0.99, "Zero-width/invisible Unicode characters detected", 12)
            detections.append("zero_width_characters")
            normalized = visible

        invisible = [c for c in normalized if unicodedata.category(c) in {"Cf", "Cc"} and c not in "\t\n\r"]
        if invisible:
            detections.append("invisible_unicode")
            risk += 8

        confusables = [c for c in normalized if ord(c) > 127 and unicodedata.category(c).startswith("L")]
        if confusables:
            detections.append("non_ascii_letters")
            suspicious.append("Non-ASCII letters may contain confusable characters")
            risk += min(8, len(confusables))

        if re.search(r"<!--.*?-->", normalized, re.S):
            detections.append("html_comments")
            suspicious.append("HTML comment content detected")
            risk += 8

        if re.search(r"<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^>]*>", normalized, re.I):
            detections.append("hidden_html_css")
            suspicious.append("Potentially hidden HTML/CSS text detected")
            risk += 12

        for match in BASE64.finditer(normalized):
            try:
                decoded = base64.b64decode(match.group(0), validate=True).decode("utf-8", "ignore")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            if decoded and any(ch.isalpha() for ch in decoded):
                add("base64", match.group(0), decoded, 0.90, "Base64-like fragment decoded successfully", 10)
                detections.append("base64")
                suspicious.append(decoded[:300])

        for match in HEX.finditer(normalized):
            raw = match.group(0)
            try:
                decoded = bytes.fromhex(raw).decode("utf-8", "ignore")
            except (ValueError, UnicodeDecodeError):
                continue
            if decoded:
                add("hex", raw, decoded, 0.88, "Hex-encoded fragment detected", 8)
                detections.append("hex")

        rot = codecs.decode(normalized, "rot_13")
        if rot != normalized and re.search(r"(?:ignore|system|instruction|password|secret)", rot, re.I) and not re.search(r"(?:ignore|system|instruction|password|secret)", normalized, re.I):
            add("rot13", normalized, rot, 0.75, "ROT13 interpretation contains security-sensitive language", 10)
            detections.append("rot13")

        if URL_ESC.search(normalized):
            decoded = unquote(normalized)
            if decoded != normalized:
                add("url_encoding", normalized, decoded, 0.95, "Percent-encoded content detected", 7)
                detections.append("url_encoding")

        if UNICODE_ESC.search(normalized):
            try:
                decoded = codecs.decode(normalized, "unicode_escape")
            except UnicodeDecodeError:
                decoded = normalized
            if decoded != normalized:
                add("unicode_escape", normalized, decoded, 0.92, "Unicode/hex escape sequences detected", 8)
                detections.append("unicode_escape")

        if "```" in normalized or re.search(r"^\s*~~~", normalized, re.M):
            detections.append("markdown_code_block")
        if re.search(r"(?:<UNTRUSTED_|</UNTRUSTED_|\[\[.*?\]\])", normalized, re.I):
            detections.append("delimiters")
        if len(normalized) > 20 and re.search(r"(.{3,})\1{3,}", normalized):
            detections.append("excessive_repetition")
            risk += 6

        return {
            "original_text": original,
            "normalized_text": normalized,
            "transformations": transformations,
            "encoding_detections": sorted(set(detections)),
            "suspicious_fragments": suspicious,
            "risk_adjustment": min(risk, 40),
        }
