"""
APT-X Data Classifier
=====================

Rule-based auto-classification for security data without ML dependencies.
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from aptx.core.logger import get_logger


class DataType(str, Enum):
    """Types of security data."""
    PAYLOAD = "payload"
    WORDLIST = "wordlist"
    DETECTION_LOGIC = "detection_logic"
    BYPASS_TECHNIQUE = "bypass"
    MISCONFIGURATION = "misconfiguration"
    FALSE_POSITIVE = "false_positive"
    TOOL_OUTPUT = "tool_output"
    WRITEUP = "writeup"
    UNKNOWN = "unknown"


class VulnCategory(str, Enum):
    """Vulnerability categories."""
    SQLI = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    FILE_UPLOAD = "file_upload"
    AUTH = "auth"
    IDOR = "idor"
    GENERAL = "general"


@dataclass
class ClassificationResult:
    """Result of data classification."""
    data_type: DataType
    category: VulnCategory
    confidence: int  # 0-100
    subcategory: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    usage_stage: Optional[str] = None  # recon, detection, validation
    explanation: str = ""


class DataClassifier:
    """
    Rule-based classifier for security data.

    Automatically determines the type and category of security-related
    content without requiring ML models.
    """

    # Payload patterns by category
    PAYLOAD_PATTERNS = {
        VulnCategory.SQLI: [
            r"['\"].*[oO][rR].*['\"]",
            r"UNION\s+SELECT",
            r"ORDER\s+BY\s+\d+",
            r"--\s*$",
            r";\s*DROP\s+TABLE",
            r"SLEEP\s*\(",
            r"BENCHMARK\s*\(",
            r"WAITFOR\s+DELAY",
            r"1\s*=\s*1",
            r"1'\s*OR\s*'1",
        ],
        VulnCategory.XSS: [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<img[^>]*onerror",
            r"<svg[^>]*onload",
            r"document\.cookie",
            r"alert\s*\(",
            r"prompt\s*\(",
            r"confirm\s*\(",
        ],
        VulnCategory.COMMAND_INJECTION: [
            r";\s*\w+",
            r"\|\s*\w+",
            r"`[^`]+`",
            r"\$\([^)]+\)",
            r"&&\s*\w+",
            r"\|\|\s*\w+",
            r"/bin/(sh|bash)",
            r"nc\s+-[elv]",
        ],
        VulnCategory.PATH_TRAVERSAL: [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e",
            r"/etc/passwd",
            r"c:\\windows",
            r"file://",
        ],
        VulnCategory.SSRF: [
            r"http://127\.0\.0\.1",
            r"http://localhost",
            r"http://\[::1\]",
            r"169\.254\.169\.254",
            r"gopher://",
            r"dict://",
            r"file:///",
        ],
        VulnCategory.XXE: [
            r"<!ENTITY",
            r"<!DOCTYPE",
            r"SYSTEM\s+[\"']",
            r"PUBLIC\s+[\"']",
            r"file://",
            r"expect://",
        ],
    }

    # Wordlist indicators
    WORDLIST_PATTERNS = [
        r"^[\w\-\.]+$",  # Simple word per line
        r"^\d+$",  # Numeric lists
        r"^[a-zA-Z]{2,20}$",  # Dictionary words
    ]

    # Detection/rule patterns
    DETECTION_PATTERNS = [
        r"(if|when|where).*then",
        r"detect|check|scan|find|match",
        r"rule\s*\{",
        r"^-\s+\w+:",  # YAML-like rules
        r"pattern:",
        r"matchers:",
    ]

    # Bypass technique patterns
    BYPASS_PATTERNS = [
        r"bypass|evade|circumvent|avoid",
        r"waf|filter|sanitiz|escape",
        r"alternative|variation|obfuscate",
        r"encoding|double.?encod",
    ]

    def __init__(self):
        self.logger = get_logger().get_child("classifier")

    def classify(self, content: str, context: Optional[Dict] = None) -> ClassificationResult:
        """
        Classify content and determine its type and category.

        Args:
            content: Content to classify
            context: Optional context (filename, source URL, etc.)

        Returns:
            ClassificationResult with type, category, and confidence
        """
        context = context or {}
        content_lower = content.lower()
        lines = content.strip().split("\n")

        # Determine data type
        data_type, type_confidence = self._classify_type(content, lines, context)

        # Determine vulnerability category
        category, cat_confidence = self._classify_category(content, context)

        # Calculate overall confidence
        confidence = (type_confidence + cat_confidence) // 2

        # Determine usage stage
        usage_stage = self._determine_usage_stage(data_type, category)

        # Extract tags
        tags = self._extract_tags(content, context)

        # Generate explanation
        explanation = self._generate_explanation(data_type, category, confidence)

        return ClassificationResult(
            data_type=data_type,
            category=category,
            confidence=confidence,
            tags=tags,
            usage_stage=usage_stage,
            explanation=explanation
        )

    def _classify_type(
        self,
        content: str,
        lines: List[str],
        context: Dict
    ) -> Tuple[DataType, int]:
        """Classify the data type."""
        scores = {dt: 0 for dt in DataType}

        # Check context hints
        filename = context.get("filename", "").lower()
        source = context.get("source", "").lower()

        if any(x in filename for x in ["payload", "fuzz"]):
            scores[DataType.PAYLOAD] += 30
        if any(x in filename for x in ["wordlist", "dict", "words"]):
            scores[DataType.WORDLIST] += 30
        if any(x in filename for x in ["bypass", "waf"]):
            scores[DataType.BYPASS_TECHNIQUE] += 30
        if any(x in filename for x in ["rule", "template", "detect"]):
            scores[DataType.DETECTION_LOGIC] += 30

        # Check content patterns

        # Wordlist detection (simple words, one per line)
        if len(lines) > 5:
            simple_lines = sum(1 for l in lines[:20] if re.match(r"^[\w\-\.]+$", l.strip()))
            if simple_lines > len(lines[:20]) * 0.7:
                scores[DataType.WORDLIST] += 50

        # Payload detection
        payload_matches = 0
        for patterns in self.PAYLOAD_PATTERNS.values():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    payload_matches += 1
        if payload_matches >= 2:
            scores[DataType.PAYLOAD] += 40

        # Detection logic
        for pattern in self.DETECTION_PATTERNS:
            if re.search(pattern, content, re.I):
                scores[DataType.DETECTION_LOGIC] += 15

        # Bypass techniques
        for pattern in self.BYPASS_PATTERNS:
            if re.search(pattern, content, re.I):
                scores[DataType.BYPASS_TECHNIQUE] += 15

        # Tool output detection
        if any(x in content for x in ["Nmap scan", "[+]", "[*]", "Starting", "Completed"]):
            scores[DataType.TOOL_OUTPUT] += 40

        # Get highest scoring type
        best_type = max(scores, key=scores.get)
        confidence = min(95, scores[best_type])

        if confidence < 20:
            return DataType.UNKNOWN, 20

        return best_type, confidence

    def _classify_category(
        self,
        content: str,
        context: Dict
    ) -> Tuple[VulnCategory, int]:
        """Classify vulnerability category."""
        scores = {vc: 0 for vc in VulnCategory}

        # Check context
        filename = context.get("filename", "").lower()

        category_hints = {
            "sql": VulnCategory.SQLI,
            "xss": VulnCategory.XSS,
            "command": VulnCategory.COMMAND_INJECTION,
            "rce": VulnCategory.COMMAND_INJECTION,
            "lfi": VulnCategory.PATH_TRAVERSAL,
            "path": VulnCategory.PATH_TRAVERSAL,
            "ssrf": VulnCategory.SSRF,
            "xxe": VulnCategory.XXE,
            "upload": VulnCategory.FILE_UPLOAD,
            "auth": VulnCategory.AUTH,
            "idor": VulnCategory.IDOR,
        }

        for hint, category in category_hints.items():
            if hint in filename:
                scores[category] += 30

        # Check payload patterns
        for category, patterns in self.PAYLOAD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    scores[category] += 10

        # Get highest scoring category
        best_category = max(scores, key=scores.get)
        confidence = min(90, scores[best_category])

        if confidence < 20:
            return VulnCategory.GENERAL, 30

        return best_category, confidence

    def _determine_usage_stage(
        self,
        data_type: DataType,
        category: VulnCategory
    ) -> str:
        """Determine when this data should be used in the pipeline."""
        if data_type == DataType.WORDLIST:
            return "recon"
        if data_type == DataType.PAYLOAD:
            return "detection"
        if data_type == DataType.DETECTION_LOGIC:
            return "detection"
        if data_type == DataType.BYPASS_TECHNIQUE:
            return "validation"
        return "detection"

    def _extract_tags(self, content: str, context: Dict) -> List[str]:
        """Extract relevant tags from content."""
        tags = []

        # From filename
        filename = context.get("filename", "")
        if filename:
            parts = re.split(r"[\-_\.\s]", filename)
            tags.extend([p.lower() for p in parts if len(p) > 2])

        # Common tags
        tag_patterns = {
            "web": r"http|web|url",
            "network": r"tcp|udp|port|socket",
            "database": r"sql|mysql|postgres|oracle",
            "authentication": r"auth|login|password|credential",
            "encoding": r"base64|hex|url.?encod",
        }

        for tag, pattern in tag_patterns.items():
            if re.search(pattern, content, re.I):
                tags.append(tag)

        return list(set(tags))[:10]

    def _generate_explanation(
        self,
        data_type: DataType,
        category: VulnCategory,
        confidence: int
    ) -> str:
        """Generate human-readable explanation of classification."""
        return (
            f"Classified as {data_type.value} data related to {category.value} "
            f"with {confidence}% confidence based on pattern matching."
        )

    def batch_classify(
        self,
        items: List[Tuple[str, Dict]]
    ) -> List[ClassificationResult]:
        """Classify multiple items."""
        return [self.classify(content, context) for content, context in items]
