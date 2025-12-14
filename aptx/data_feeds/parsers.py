"""
APT-X Data Parsers
==================

Parsers for processing intelligence data into structured formats.
"""

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional
from dataclasses import dataclass, field

import yaml

from aptx.core.logger import get_logger
from aptx.data_feeds.sources import SourceItem


@dataclass
class ParsedItem:
    """Parsed intelligence item."""
    data_type: str  # payload, wordlist, bypass, detection_logic, template
    category: str   # sqli, xss, lfi, etc.
    content: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    source: str = ""


class DataParser(ABC):
    """Abstract base class for data parsers."""

    parser_type: str = "base"
    supported_extensions: List[str] = []

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = get_logger().get_child(f"parser.{self.parser_type}")

    @abstractmethod
    def parse(self, item: SourceItem) -> Iterator[ParsedItem]:
        """
        Parse source item into structured data.

        Args:
            item: Source item to parse

        Yields:
            ParsedItem objects
        """
        pass

    def can_parse(self, item: SourceItem) -> bool:
        """Check if parser can handle this item."""
        ext = item.metadata.get("extension", "")
        filename = item.metadata.get("filename", "")

        if self.supported_extensions and ext not in self.supported_extensions:
            return False

        return True


class PayloadParser(DataParser):
    """Parser for payload files (SQLi, XSS, etc.)."""

    parser_type = "payload"
    supported_extensions = [".txt", ".json", ".yaml", ".yml"]

    # Category detection patterns
    CATEGORY_PATTERNS = {
        "sqli": [r"sql", r"injection", r"sqli", r"mysql", r"oracle", r"mssql"],
        "xss": [r"xss", r"cross.?site", r"script", r"alert\(", r"<script"],
        "lfi": [r"lfi", r"local.?file", r"path.?traversal", r"\.\./"],
        "rfi": [r"rfi", r"remote.?file", r"include"],
        "rce": [r"rce", r"command", r"exec", r"shell", r"cmd"],
        "ssrf": [r"ssrf", r"server.?side", r"request.?forgery"],
        "xxe": [r"xxe", r"xml", r"entity", r"<!ENTITY"],
        "ssti": [r"ssti", r"template", r"jinja", r"{{"],
        "nosqli": [r"nosql", r"mongo", r"[\$]"],
    }

    def parse(self, item: SourceItem) -> Iterator[ParsedItem]:
        """Parse payload file."""
        ext = item.metadata.get("extension", "").lower()
        filename = item.metadata.get("filename", "").lower()

        # Detect category from filename or path
        category = self._detect_category(item.source_path, item.content[:1000])

        if ext == ".json":
            yield from self._parse_json(item, category)
        elif ext in [".yaml", ".yml"]:
            yield from self._parse_yaml(item, category)
        else:
            yield from self._parse_text(item, category)

    def _detect_category(self, path: str, content_sample: str) -> str:
        """Detect payload category from path and content."""
        combined = f"{path} {content_sample}".lower()

        for category, patterns in self.CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return category

        return "generic"

    def _parse_text(self, item: SourceItem, category: str) -> Iterator[ParsedItem]:
        """Parse text file with one payload per line."""
        lines = item.content.strip().split("\n")
        payloads = []

        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if line and not line.startswith("#"):
                payloads.append(line)

        if payloads:
            yield ParsedItem(
                data_type="payload",
                category=category,
                content=payloads,
                metadata={
                    "count": len(payloads),
                    "filename": item.metadata.get("filename", ""),
                },
                source=item.source_path
            )

    def _parse_json(self, item: SourceItem, category: str) -> Iterator[ParsedItem]:
        """Parse JSON payload file."""
        try:
            data = json.loads(item.content)

            if isinstance(data, list):
                yield ParsedItem(
                    data_type="payload",
                    category=category,
                    content=data,
                    metadata={"count": len(data)},
                    source=item.source_path
                )
            elif isinstance(data, dict):
                # Handle structured payload files
                for key, payloads in data.items():
                    if isinstance(payloads, list):
                        yield ParsedItem(
                            data_type="payload",
                            category=key if key in self.CATEGORY_PATTERNS else category,
                            content=payloads,
                            metadata={"count": len(payloads), "key": key},
                            source=item.source_path
                        )

        except json.JSONDecodeError as e:
            self.logger.warning(f"JSON parse error: {e}")

    def _parse_yaml(self, item: SourceItem, category: str) -> Iterator[ParsedItem]:
        """Parse YAML payload file."""
        try:
            data = yaml.safe_load(item.content)

            if isinstance(data, list):
                yield ParsedItem(
                    data_type="payload",
                    category=category,
                    content=data,
                    metadata={"count": len(data)},
                    source=item.source_path
                )
            elif isinstance(data, dict):
                payloads = data.get("payloads", data.get("data", []))
                if payloads:
                    yield ParsedItem(
                        data_type="payload",
                        category=data.get("category", category),
                        content=payloads,
                        metadata=data.get("metadata", {}),
                        tags=data.get("tags", []),
                        source=item.source_path
                    )

        except yaml.YAMLError as e:
            self.logger.warning(f"YAML parse error: {e}")


class WordlistParser(DataParser):
    """Parser for wordlist files."""

    parser_type = "wordlist"
    supported_extensions = [".txt", ".lst"]

    # Wordlist type patterns
    TYPE_PATTERNS = {
        "directories": [r"dir", r"folder", r"path", r"common"],
        "files": [r"file", r"backup", r"extension"],
        "parameters": [r"param", r"query", r"argument"],
        "usernames": [r"user", r"name", r"login", r"account"],
        "passwords": [r"pass", r"pwd", r"secret"],
        "subdomains": [r"subdomain", r"dns", r"vhost"],
        "api": [r"api", r"endpoint", r"route"],
    }

    def parse(self, item: SourceItem) -> Iterator[ParsedItem]:
        """Parse wordlist file."""
        filename = item.metadata.get("filename", "").lower()
        path = item.source_path.lower()

        # Detect wordlist type
        wordlist_type = self._detect_type(path, filename)

        lines = item.content.strip().split("\n")
        words = []

        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)

        if words:
            yield ParsedItem(
                data_type="wordlist",
                category=wordlist_type,
                content=words,
                metadata={
                    "count": len(words),
                    "filename": item.metadata.get("filename", ""),
                },
                source=item.source_path
            )

    def _detect_type(self, path: str, filename: str) -> str:
        """Detect wordlist type."""
        combined = f"{path} {filename}"

        for wl_type, patterns in self.TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return wl_type

        return "general"


class NucleiTemplateParser(DataParser):
    """Parser for Nuclei YAML templates."""

    parser_type = "nuclei"
    supported_extensions = [".yaml", ".yml"]

    def parse(self, item: SourceItem) -> Iterator[ParsedItem]:
        """Parse Nuclei template."""
        try:
            data = yaml.safe_load(item.content)

            if not isinstance(data, dict):
                return

            # Check if it's a Nuclei template
            if "id" not in data:
                return

            template_id = data.get("id", "")
            info = data.get("info", {})

            # Extract detection logic
            detection_logic = {
                "id": template_id,
                "name": info.get("name", ""),
                "severity": info.get("severity", "info"),
                "description": info.get("description", ""),
                "tags": info.get("tags", []),
                "author": info.get("author", ""),
                "reference": info.get("reference", []),
            }

            # Extract request patterns
            if "http" in data:
                http_reqs = data["http"]
                if isinstance(http_reqs, list):
                    detection_logic["http_requests"] = []
                    for req in http_reqs:
                        req_info = {
                            "method": req.get("method", "GET"),
                            "path": req.get("path", []),
                            "matchers": req.get("matchers", []),
                            "extractors": req.get("extractors", []),
                        }
                        detection_logic["http_requests"].append(req_info)

            # Determine category from tags
            category = self._detect_category(info.get("tags", []))

            yield ParsedItem(
                data_type="detection_logic",
                category=category,
                content=detection_logic,
                metadata={
                    "template_id": template_id,
                    "severity": info.get("severity", "info"),
                },
                tags=info.get("tags", []) if isinstance(info.get("tags"), list) else [],
                source=item.source_path
            )

        except yaml.YAMLError as e:
            self.logger.debug(f"YAML parse error: {e}")

    def _detect_category(self, tags: List[str]) -> str:
        """Detect category from Nuclei tags."""
        tag_str = " ".join(tags).lower()

        category_map = {
            "sqli": ["sqli", "sql-injection"],
            "xss": ["xss", "cross-site-scripting"],
            "lfi": ["lfi", "local-file-inclusion"],
            "rce": ["rce", "remote-code-execution"],
            "ssrf": ["ssrf"],
            "xxe": ["xxe"],
            "cve": ["cve"],
            "exposure": ["exposure", "disclosure"],
            "misconfig": ["misconfig", "misconfiguration"],
            "default-login": ["default-login"],
        }

        for category, keywords in category_map.items():
            for keyword in keywords:
                if keyword in tag_str:
                    return category

        return "other"


class BypassParser(DataParser):
    """Parser for WAF/filter bypass techniques."""

    parser_type = "bypass"
    supported_extensions = [".txt", ".json", ".yaml", ".yml"]

    def parse(self, item: SourceItem) -> Iterator[ParsedItem]:
        """Parse bypass technique file."""
        filename = item.metadata.get("filename", "").lower()
        ext = item.metadata.get("extension", "").lower()

        # Determine bypass category
        category = "waf"
        if "403" in filename or "forbidden" in filename:
            category = "403_bypass"
        elif "filter" in filename:
            category = "filter_bypass"
        elif "encoding" in filename:
            category = "encoding"

        if ext == ".json":
            try:
                data = json.loads(item.content)
                yield ParsedItem(
                    data_type="bypass",
                    category=category,
                    content=data if isinstance(data, list) else [data],
                    source=item.source_path
                )
            except json.JSONDecodeError:
                pass
        elif ext in [".yaml", ".yml"]:
            try:
                data = yaml.safe_load(item.content)
                if isinstance(data, dict):
                    yield ParsedItem(
                        data_type="bypass",
                        category=data.get("category", category),
                        content=data.get("techniques", data.get("bypasses", [])),
                        metadata=data.get("metadata", {}),
                        source=item.source_path
                    )
            except yaml.YAMLError:
                pass
        else:
            # Text file with one bypass per line
            lines = [l.strip() for l in item.content.split("\n")
                     if l.strip() and not l.startswith("#")]
            if lines:
                yield ParsedItem(
                    data_type="bypass",
                    category=category,
                    content=lines,
                    source=item.source_path
                )


def get_parser(parser_type: str, config: Optional[Dict] = None) -> DataParser:
    """
    Get data parser by type.

    Args:
        parser_type: Parser type
        config: Parser configuration

    Returns:
        DataParser instance
    """
    parsers = {
        "payload": PayloadParser,
        "wordlist": WordlistParser,
        "nuclei": NucleiTemplateParser,
        "bypass": BypassParser,
    }

    parser_class = parsers.get(parser_type)
    if not parser_class:
        raise ValueError(f"Unknown parser type: {parser_type}")

    return parser_class(config)


def auto_detect_parser(item: SourceItem) -> Optional[DataParser]:
    """
    Auto-detect appropriate parser for source item.

    Args:
        item: Source item

    Returns:
        Appropriate DataParser or None
    """
    filename = item.metadata.get("filename", "").lower()
    path = item.source_path.lower()
    ext = item.metadata.get("extension", "").lower()

    # Check for Nuclei templates
    if ext in [".yaml", ".yml"]:
        if "nuclei" in path or "template" in path:
            return NucleiTemplateParser()
        # Try to detect from content
        if "id:" in item.content[:500] and "info:" in item.content[:500]:
            return NucleiTemplateParser()

    # Check for wordlists
    if any(kw in path for kw in ["wordlist", "seclists", "dictionary"]):
        return WordlistParser()

    # Check for bypass files
    if any(kw in filename for kw in ["bypass", "waf", "filter", "403"]):
        return BypassParser()

    # Default to payload parser
    if ext in [".txt", ".json", ".yaml", ".yml"]:
        return PayloadParser()

    return None
