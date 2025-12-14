"""
APT-X Data Normalizer
=====================

Normalize and deduplicate security data.
"""

import re
import hashlib
from typing import List, Optional
from urllib.parse import unquote


class DataNormalizer:
    """Normalize security data for consistent storage and comparison."""

    @staticmethod
    def normalize_payload(payload: str) -> str:
        """Normalize a payload string."""
        # Remove whitespace variations
        normalized = " ".join(payload.split())
        # Decode URL encoding
        normalized = unquote(normalized)
        # Lowercase for comparison (but keep original for use)
        return normalized.strip()

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize a URL."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url.lower())
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/"),
            parsed.params,
            parsed.query,
            ""  # Remove fragment
        ))
        return normalized

    @staticmethod
    def compute_hash(content: str) -> str:
        """Compute content hash for deduplication."""
        normalized = DataNormalizer.normalize_payload(content)
        return hashlib.sha256(normalized.encode()).hexdigest()

    @staticmethod
    def extract_patterns(content: str) -> List[str]:
        """Extract reusable patterns from content."""
        patterns = []

        # SQL patterns
        sql_patterns = re.findall(
            r"(UNION\s+SELECT|ORDER\s+BY|WHERE\s+\d|OR\s+['\"]\d)",
            content, re.I
        )
        patterns.extend(sql_patterns)

        # XSS patterns
        xss_patterns = re.findall(
            r"(<script[^>]*>|on\w+\s*=|javascript:)",
            content, re.I
        )
        patterns.extend(xss_patterns)

        return list(set(patterns))
