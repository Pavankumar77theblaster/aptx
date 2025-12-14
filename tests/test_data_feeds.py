"""
Tests for APT-X Data Feeds Module
=================================
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aptx.data_feeds.sources import (
    DataSource,
    FileSource,
    URLSource,
    GitHubSource,
    SourceItem,
    get_source,
)
from aptx.data_feeds.parsers import (
    DataParser,
    PayloadParser,
    WordlistParser,
    NucleiTemplateParser,
    BypassParser,
    ParsedItem,
    auto_detect_parser,
    get_parser,
)
from aptx.data_feeds.ingestor import DataIngestor, IngestResult


class TestSourceItem:
    """Test cases for SourceItem."""

    def test_source_item_creation(self):
        """Test SourceItem creation."""
        item = SourceItem(
            content="test content",
            metadata={"filename": "test.txt"},
            source_type="file",
            source_path="/path/to/test.txt"
        )

        assert item.content == "test content"
        assert item.metadata["filename"] == "test.txt"
        assert item.source_type == "file"


class TestFileSource:
    """Test cases for FileSource."""

    def test_file_source_validate_exists(self, temp_dir):
        """Test file source validation for existing file."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        source = FileSource()
        assert source.validate(str(test_file)) is True

    def test_file_source_validate_not_exists(self):
        """Test file source validation for non-existent file."""
        source = FileSource()
        assert source.validate("/nonexistent/path/file.txt") is False

    def test_file_source_fetch_file(self, temp_dir):
        """Test fetching from a file."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("payload1\npayload2")

        source = FileSource()
        items = list(source.fetch(str(test_file)))

        assert len(items) == 1
        assert "payload1" in items[0].content

    def test_file_source_fetch_directory(self, temp_dir):
        """Test fetching from a directory."""
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.txt").write_text("content2")

        source = FileSource()
        items = list(source.fetch(str(temp_dir)))

        assert len(items) == 2


class TestURLSource:
    """Test cases for URLSource."""

    def test_url_source_initialization(self):
        """Test URL source initialization."""
        source = URLSource()
        assert source.timeout == 30
        assert "User-Agent" in source.headers

    @patch("httpx.Client")
    def test_url_source_fetch(self, mock_client_class):
        """Test URL source fetch."""
        mock_response = MagicMock()
        mock_response.text = "test content"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/plain"}
        mock_response.content = b"test content"
        mock_response.url = "http://example.com/file.txt"

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        source = URLSource()
        items = list(source.fetch("http://example.com/file.txt"))

        assert len(items) == 1
        assert items[0].content == "test content"


class TestGitHubSource:
    """Test cases for GitHubSource."""

    def test_parse_location_simple(self):
        """Test parsing simple GitHub location."""
        source = GitHubSource()
        result = source._parse_location("owner/repo")

        assert result[0] == "owner"
        assert result[1] == "repo"
        assert result[2] == ""  # path
        assert result[3] == "main"  # branch

    def test_parse_location_with_path(self):
        """Test parsing GitHub location with path."""
        source = GitHubSource()
        result = source._parse_location("owner/repo/path/to/file")

        assert result[0] == "owner"
        assert result[1] == "repo"
        assert result[2] == "path/to/file"

    def test_parse_location_full_url(self):
        """Test parsing full GitHub URL."""
        source = GitHubSource()
        result = source._parse_location("https://github.com/owner/repo/tree/main/path")

        assert result[0] == "owner"
        assert result[1] == "repo"


class TestGetSource:
    """Test cases for get_source function."""

    def test_get_file_source(self):
        """Test getting file source."""
        source = get_source("file")
        assert isinstance(source, FileSource)

    def test_get_url_source(self):
        """Test getting URL source."""
        source = get_source("url")
        assert isinstance(source, URLSource)

    def test_get_github_source(self):
        """Test getting GitHub source."""
        source = get_source("github")
        assert isinstance(source, GitHubSource)

    def test_get_unknown_source(self):
        """Test getting unknown source type."""
        with pytest.raises(ValueError):
            get_source("unknown")


class TestParsedItem:
    """Test cases for ParsedItem."""

    def test_parsed_item_creation(self):
        """Test ParsedItem creation."""
        item = ParsedItem(
            data_type="payload",
            category="sqli",
            content=["'", "\""],
            metadata={"count": 2}
        )

        assert item.data_type == "payload"
        assert item.category == "sqli"
        assert len(item.content) == 2


class TestPayloadParser:
    """Test cases for PayloadParser."""

    def test_parse_text_payloads(self):
        """Test parsing text payload file."""
        parser = PayloadParser()
        item = SourceItem(
            content="'\n\"\n' OR '1'='1",
            metadata={"extension": ".txt", "filename": "sqli.txt"},
            source_type="file",
            source_path="/path/sqli.txt"
        )

        parsed = list(parser.parse(item))
        assert len(parsed) == 1
        assert parsed[0].data_type == "payload"
        assert parsed[0].category == "sqli"
        assert len(parsed[0].content) == 3

    def test_parse_json_payloads(self):
        """Test parsing JSON payload file."""
        parser = PayloadParser()
        item = SourceItem(
            content='["payload1", "payload2"]',
            metadata={"extension": ".json", "filename": "payloads.json"},
            source_type="file",
            source_path="/path/payloads.json"
        )

        parsed = list(parser.parse(item))
        assert len(parsed) == 1
        assert len(parsed[0].content) == 2

    def test_detect_category(self):
        """Test category detection."""
        parser = PayloadParser()

        assert parser._detect_category("/sqli/payloads.txt", "") == "sqli"
        assert parser._detect_category("/xss/test.txt", "<script>") == "xss"
        assert parser._detect_category("/other/file.txt", "normal") == "generic"


class TestWordlistParser:
    """Test cases for WordlistParser."""

    def test_parse_wordlist(self):
        """Test parsing wordlist file."""
        parser = WordlistParser()
        item = SourceItem(
            content="admin\nlogin\npassword",
            metadata={"extension": ".txt", "filename": "common.txt"},
            source_type="file",
            source_path="/wordlists/common.txt"
        )

        parsed = list(parser.parse(item))
        assert len(parsed) == 1
        assert parsed[0].data_type == "wordlist"
        assert len(parsed[0].content) == 3

    def test_detect_type(self):
        """Test wordlist type detection."""
        parser = WordlistParser()

        assert parser._detect_type("/path/directories.txt", "directories") == "directories"
        assert parser._detect_type("/path/usernames.txt", "usernames") == "usernames"


class TestNucleiTemplateParser:
    """Test cases for NucleiTemplateParser."""

    def test_parse_nuclei_template(self):
        """Test parsing Nuclei template."""
        template_content = """
id: test-template
info:
  name: Test Template
  severity: high
  tags: sqli,injection
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        words:
          - "error"
"""
        parser = NucleiTemplateParser()
        item = SourceItem(
            content=template_content,
            metadata={"extension": ".yaml", "filename": "test.yaml"},
            source_type="file",
            source_path="/templates/test.yaml"
        )

        parsed = list(parser.parse(item))
        assert len(parsed) == 1
        assert parsed[0].data_type == "detection_logic"
        assert parsed[0].content["id"] == "test-template"


class TestAutoDetectParser:
    """Test cases for auto_detect_parser function."""

    def test_auto_detect_nuclei(self):
        """Test auto-detecting Nuclei template."""
        item = SourceItem(
            content="id: test\ninfo:\n  name: Test",
            metadata={"extension": ".yaml", "filename": "test.yaml"},
            source_type="file",
            source_path="/nuclei-templates/test.yaml"
        )

        parser = auto_detect_parser(item)
        assert isinstance(parser, NucleiTemplateParser)

    def test_auto_detect_wordlist(self):
        """Test auto-detecting wordlist."""
        item = SourceItem(
            content="word1\nword2",
            metadata={"extension": ".txt", "filename": "common.txt"},
            source_type="file",
            source_path="/seclists/wordlist.txt"
        )

        parser = auto_detect_parser(item)
        assert isinstance(parser, WordlistParser)

    def test_auto_detect_bypass(self):
        """Test auto-detecting bypass file."""
        item = SourceItem(
            content="bypass1\nbypass2",
            metadata={"extension": ".txt", "filename": "403_bypass.txt"},
            source_type="file",
            source_path="/bypasses/403_bypass.txt"
        )

        parser = auto_detect_parser(item)
        assert isinstance(parser, BypassParser)


class TestDataIngestor:
    """Test cases for DataIngestor."""

    def test_ingestor_initialization(self):
        """Test ingestor initialization."""
        ingestor = DataIngestor()
        assert ingestor.config == {}

    def test_detect_source_type(self):
        """Test source type detection."""
        ingestor = DataIngestor()

        assert ingestor._detect_source_type("http://example.com/file.txt") == "url"
        assert ingestor._detect_source_type("https://github.com/owner/repo") == "github"
        assert ingestor._detect_source_type("owner/repo") == "github"
        assert ingestor._detect_source_type("/path/to/file.txt") == "file"

    def test_ingest_from_file(self, temp_dir, clean_database):
        """Test ingesting from local file."""
        # Create test file
        test_file = temp_dir / "payloads.txt"
        test_file.write_text("' OR '1'='1\n\" OR \"1\"=\"1")

        ingestor = DataIngestor()
        result = ingestor.ingest(str(test_file))

        assert result.success is True
        assert result.items_fetched >= 1


class TestIngestResult:
    """Test cases for IngestResult."""

    def test_ingest_result_creation(self):
        """Test IngestResult creation."""
        result = IngestResult(
            success=True,
            source="test.txt",
            items_fetched=10,
            items_parsed=8,
            items_added=5
        )

        assert result.success is True
        assert result.items_added == 5

    def test_ingest_result_to_dict(self):
        """Test converting IngestResult to dictionary."""
        result = IngestResult(
            success=True,
            source="test.txt"
        )

        result_dict = result.to_dict()
        assert result_dict["success"] is True
        assert result_dict["source"] == "test.txt"
