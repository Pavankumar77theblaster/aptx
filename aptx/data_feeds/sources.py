"""
APT-X Data Sources
==================

Data source adapters for fetching intelligence data from various sources.
"""

import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from dataclasses import dataclass

from aptx.core.logger import get_logger


@dataclass
class SourceItem:
    """Item fetched from a data source."""
    content: str
    metadata: Dict[str, Any]
    source_type: str
    source_path: str


class DataSource(ABC):
    """Abstract base class for data sources."""

    source_type: str = "base"

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = get_logger().get_child(f"source.{self.source_type}")

    @abstractmethod
    def fetch(self, location: str) -> Iterator[SourceItem]:
        """
        Fetch data from the source.

        Args:
            location: Source location (path, URL, etc.)

        Yields:
            SourceItem objects
        """
        pass

    @abstractmethod
    def validate(self, location: str) -> bool:
        """
        Validate if location is accessible.

        Args:
            location: Source location

        Returns:
            True if location is valid
        """
        pass


class FileSource(DataSource):
    """Local file/directory data source."""

    source_type = "file"

    SUPPORTED_EXTENSIONS = [".txt", ".yaml", ".yml", ".json", ".csv"]

    def fetch(self, location: str) -> Iterator[SourceItem]:
        """Fetch data from local file or directory."""
        path = Path(location)

        if not path.exists():
            self.logger.error(f"Path not found: {location}")
            return

        if path.is_file():
            yield from self._read_file(path)
        elif path.is_dir():
            yield from self._read_directory(path)

    def _read_file(self, file_path: Path) -> Iterator[SourceItem]:
        """Read single file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            yield SourceItem(
                content=content,
                metadata={
                    "filename": file_path.name,
                    "extension": file_path.suffix,
                    "size": file_path.stat().st_size,
                },
                source_type=self.source_type,
                source_path=str(file_path)
            )
        except Exception as e:
            self.logger.error(f"Error reading {file_path}: {e}")

    def _read_directory(self, dir_path: Path) -> Iterator[SourceItem]:
        """Read all supported files in directory."""
        for file_path in dir_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in self.SUPPORTED_EXTENSIONS:
                yield from self._read_file(file_path)

    def validate(self, location: str) -> bool:
        """Validate file/directory exists."""
        return Path(location).exists()


class URLSource(DataSource):
    """HTTP/HTTPS URL data source."""

    source_type = "url"

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 30)
        self.headers = self.config.get("headers", {
            "User-Agent": "APT-X Intelligence Fetcher/1.0"
        })

    def fetch(self, location: str) -> Iterator[SourceItem]:
        """Fetch data from URL."""
        import httpx

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(location, headers=self.headers)
                response.raise_for_status()

                yield SourceItem(
                    content=response.text,
                    metadata={
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "content_length": len(response.content),
                    },
                    source_type=self.source_type,
                    source_path=location
                )

        except Exception as e:
            self.logger.error(f"Error fetching {location}: {e}")

    def validate(self, location: str) -> bool:
        """Validate URL is accessible."""
        import httpx

        try:
            with httpx.Client(timeout=10) as client:
                response = client.head(location, follow_redirects=True)
                return response.status_code < 400
        except Exception:
            return False


class GitHubSource(DataSource):
    """GitHub repository data source."""

    source_type = "github"

    GITHUB_RAW_BASE = "https://raw.githubusercontent.com"
    GITHUB_API_BASE = "https://api.github.com"

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.token = self.config.get("token", os.environ.get("GITHUB_TOKEN", ""))
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    def fetch(self, location: str) -> Iterator[SourceItem]:
        """
        Fetch data from GitHub repository.

        Location format: owner/repo or owner/repo/path or full GitHub URL
        """
        import httpx

        # Parse location
        repo_info = self._parse_location(location)
        if not repo_info:
            self.logger.error(f"Invalid GitHub location: {location}")
            return

        owner, repo, path, branch = repo_info

        # Get file list
        files = self._list_files(owner, repo, path, branch)

        # Fetch each file
        with httpx.Client(timeout=30, headers=self.headers) as client:
            for file_info in files:
                if file_info["type"] != "file":
                    continue

                # Skip large files
                if file_info.get("size", 0) > 1_000_000:  # 1MB limit
                    continue

                try:
                    # Fetch raw content
                    raw_url = f"{self.GITHUB_RAW_BASE}/{owner}/{repo}/{branch}/{file_info['path']}"
                    response = client.get(raw_url)

                    if response.status_code == 200:
                        yield SourceItem(
                            content=response.text,
                            metadata={
                                "repo": f"{owner}/{repo}",
                                "path": file_info["path"],
                                "sha": file_info.get("sha", ""),
                                "size": file_info.get("size", 0),
                            },
                            source_type=self.source_type,
                            source_path=raw_url
                        )

                except Exception as e:
                    self.logger.debug(f"Error fetching {file_info['path']}: {e}")

    def _parse_location(self, location: str) -> Optional[tuple]:
        """Parse GitHub location to (owner, repo, path, branch)."""
        import re

        # Remove github.com prefix if present
        location = re.sub(r"^https?://github\.com/", "", location)
        location = location.strip("/")

        parts = location.split("/")
        if len(parts) < 2:
            return None

        owner = parts[0]
        repo = parts[1]
        path = "/".join(parts[2:]) if len(parts) > 2 else ""
        branch = self.config.get("branch", "main")

        # Handle tree/blob in path
        if len(parts) > 3 and parts[2] in ("tree", "blob"):
            branch = parts[3]
            path = "/".join(parts[4:]) if len(parts) > 4 else ""

        return owner, repo, path, branch

    def _list_files(
        self,
        owner: str,
        repo: str,
        path: str = "",
        branch: str = "main"
    ) -> List[Dict]:
        """List files in repository path."""
        import httpx

        files = []
        url = f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": branch}

        try:
            with httpx.Client(timeout=30, headers=self.headers) as client:
                response = client.get(url, params=params)

                if response.status_code == 200:
                    data = response.json()

                    if isinstance(data, list):
                        for item in data:
                            if item["type"] == "file":
                                files.append(item)
                            elif item["type"] == "dir":
                                # Recursively get files in subdirectories
                                subfiles = self._list_files(
                                    owner, repo, item["path"], branch
                                )
                                files.extend(subfiles)
                    elif isinstance(data, dict):
                        files.append(data)

        except Exception as e:
            self.logger.error(f"Error listing files: {e}")

        return files

    def validate(self, location: str) -> bool:
        """Validate GitHub repository is accessible."""
        repo_info = self._parse_location(location)
        if not repo_info:
            return False

        owner, repo, _, _ = repo_info

        import httpx
        try:
            url = f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}"
            with httpx.Client(timeout=10, headers=self.headers) as client:
                response = client.get(url)
                return response.status_code == 200
        except Exception:
            return False


def get_source(source_type: str, config: Optional[Dict] = None) -> DataSource:
    """
    Get data source by type.

    Args:
        source_type: Source type (file, url, github)
        config: Source configuration

    Returns:
        DataSource instance
    """
    sources = {
        "file": FileSource,
        "url": URLSource,
        "github": GitHubSource,
    }

    source_class = sources.get(source_type)
    if not source_class:
        raise ValueError(f"Unknown source type: {source_type}")

    return source_class(config)
