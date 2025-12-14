"""
APT-X Data Ingestor
===================

Main module for ingesting intelligence data from various sources.
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from aptx.core.logger import get_logger
from aptx.core.database import get_database
from aptx.data_feeds.sources import DataSource, get_source, SourceItem
from aptx.data_feeds.parsers import (
    DataParser,
    ParsedItem,
    auto_detect_parser,
    get_parser,
)


@dataclass
class IngestResult:
    """Result from data ingestion."""
    success: bool
    source: str
    items_fetched: int = 0
    items_parsed: int = 0
    items_added: int = 0
    items_updated: int = 0
    items_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "source": self.source,
            "items_fetched": self.items_fetched,
            "items_parsed": self.items_parsed,
            "items_added": self.items_added,
            "items_updated": self.items_updated,
            "items_skipped": self.items_skipped,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }


class DataIngestor:
    """
    Main data ingestion engine.

    Orchestrates fetching, parsing, and storing intelligence data.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize data ingestor.

        Args:
            config: Ingestor configuration
        """
        self.config = config or {}
        self.logger = get_logger().get_child("ingestor")
        self.db = get_database()

    def ingest(
        self,
        source: str,
        source_type: Optional[str] = None,
        parser_type: Optional[str] = None,
        options: Optional[Dict] = None
    ) -> IngestResult:
        """
        Ingest data from a source.

        Args:
            source: Source location (path, URL, or GitHub repo)
            source_type: Source type (file, url, github) - auto-detected if None
            parser_type: Parser type - auto-detected if None
            options: Additional options

        Returns:
            IngestResult with statistics
        """
        started = datetime.utcnow()
        options = options or {}

        result = IngestResult(success=False, source=source)

        try:
            # Auto-detect source type
            if source_type is None:
                source_type = self._detect_source_type(source)

            self.logger.info(f"Ingesting from {source_type}: {source}")

            # Get source adapter
            source_adapter = get_source(source_type, self.config.get("sources", {}))

            if not source_adapter.validate(source):
                result.errors.append(f"Source not accessible: {source}")
                return result

            # Fetch and process items
            for item in source_adapter.fetch(source):
                result.items_fetched += 1

                # Get parser
                parser = None
                if parser_type:
                    parser = get_parser(parser_type)
                else:
                    parser = auto_detect_parser(item)

                if not parser:
                    self.logger.debug(f"No parser for: {item.source_path}")
                    result.items_skipped += 1
                    continue

                # Parse item
                try:
                    for parsed in parser.parse(item):
                        result.items_parsed += 1

                        # Store in database
                        stored = self._store_item(parsed, options)
                        if stored == "added":
                            result.items_added += 1
                        elif stored == "updated":
                            result.items_updated += 1
                        else:
                            result.items_skipped += 1

                except Exception as e:
                    self.logger.warning(f"Parse error for {item.source_path}: {e}")
                    result.errors.append(f"Parse error: {e}")

            result.success = True

        except Exception as e:
            self.logger.error(f"Ingest failed: {e}")
            result.errors.append(str(e))

        completed = datetime.utcnow()
        result.duration_seconds = (completed - started).total_seconds()

        self.logger.info(
            f"Ingest complete: {result.items_added} added, "
            f"{result.items_updated} updated, {result.items_skipped} skipped"
        )

        return result

    def ingest_multiple(
        self,
        sources: List[Dict[str, str]],
        options: Optional[Dict] = None
    ) -> List[IngestResult]:
        """
        Ingest from multiple sources.

        Args:
            sources: List of source specifications
            options: Common options

        Returns:
            List of IngestResult
        """
        results = []

        for source_spec in sources:
            source = source_spec.get("source", "")
            source_type = source_spec.get("type")
            parser_type = source_spec.get("parser")

            if source:
                result = self.ingest(source, source_type, parser_type, options)
                results.append(result)

        return results

    def _detect_source_type(self, source: str) -> str:
        """Auto-detect source type from source string."""
        source_lower = source.lower()

        if source_lower.startswith(("http://", "https://")):
            if "github.com" in source_lower:
                return "github"
            return "url"

        if "/" in source and not source.startswith("/"):
            # Could be GitHub repo format (owner/repo)
            parts = source.split("/")
            if len(parts) >= 2 and not any(c in parts[0] for c in [".", "\\", ":"]):
                return "github"

        return "file"

    def _store_item(self, item: ParsedItem, options: Dict) -> str:
        """
        Store parsed item in database.

        Args:
            item: Parsed item to store
            options: Storage options

        Returns:
            "added", "updated", or "skipped"
        """
        # Generate content hash for deduplication
        content_str = str(item.content)
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:32]

        # Check if already exists
        existing = self.db.get_intelligence(
            data_type=item.data_type,
            category=item.category,
            content_hash=content_hash
        )

        if existing:
            if options.get("update_existing", False):
                self.db.update_intelligence(
                    existing[0]["id"],
                    content=item.content,
                    metadata=item.metadata,
                    updated_at=datetime.utcnow()
                )
                return "updated"
            return "skipped"

        # Add new item
        self.db.add_intelligence(
            data_type=item.data_type,
            category=item.category,
            content=item.content,
            metadata=item.metadata,
            tags=item.tags,
            source=item.source,
            content_hash=content_hash
        )

        return "added"

    def get_stats(self) -> Dict[str, Any]:
        """Get ingestion statistics."""
        stats = {
            "by_type": {},
            "by_category": {},
            "total_items": 0,
        }

        for data_type in ["payload", "wordlist", "bypass", "detection_logic"]:
            items = self.db.get_intelligence(data_type=data_type)
            count = len(items)
            stats["by_type"][data_type] = count
            stats["total_items"] += count

            # Count by category
            for item in items:
                cat = item.get("category", "unknown")
                stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        return stats

    def clear(self, data_type: Optional[str] = None, category: Optional[str] = None):
        """
        Clear intelligence data.

        Args:
            data_type: Optional type filter
            category: Optional category filter
        """
        self.db.clear_intelligence(data_type=data_type, category=category)
        self.logger.info(
            f"Cleared intelligence data: type={data_type}, category={category}"
        )


# Built-in sources for common intelligence feeds
BUILTIN_SOURCES = [
    {
        "name": "PayloadsAllTheThings",
        "source": "swisskyrepo/PayloadsAllTheThings",
        "type": "github",
        "description": "A list of useful payloads and bypass for Web Application Security",
    },
    {
        "name": "SecLists",
        "source": "danielmiessler/SecLists",
        "type": "github",
        "description": "Collection of multiple types of lists for security assessments",
    },
    {
        "name": "Nuclei Templates",
        "source": "projectdiscovery/nuclei-templates",
        "type": "github",
        "parser": "nuclei",
        "description": "Community curated list of nuclei templates",
    },
    {
        "name": "FuzzDB",
        "source": "fuzzdb-project/fuzzdb",
        "type": "github",
        "description": "Dictionary of attack patterns and primitives",
    },
]


def get_builtin_sources() -> List[Dict]:
    """Get list of built-in intelligence sources."""
    return BUILTIN_SOURCES.copy()
