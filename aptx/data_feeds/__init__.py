"""
APT-X Data Feeds Module
=======================

Intelligence data ingestion from external sources.
Supports payloads, wordlists, bypass techniques, and detection logic.
"""

from aptx.data_feeds.ingestor import DataIngestor
from aptx.data_feeds.sources import (
    DataSource,
    FileSource,
    URLSource,
    GitHubSource,
)
from aptx.data_feeds.parsers import (
    DataParser,
    PayloadParser,
    WordlistParser,
    NucleiTemplateParser,
)

__all__ = [
    "DataIngestor",
    "DataSource",
    "FileSource",
    "URLSource",
    "GitHubSource",
    "DataParser",
    "PayloadParser",
    "WordlistParser",
    "NucleiTemplateParser",
]
