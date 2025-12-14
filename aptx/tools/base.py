"""
APT-X Tool Wrapper Base
=======================

Abstract base class for wrapping external security tools.
Provides standardized execution, output parsing, and error handling.
"""

import os
import json
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import asyncio

from aptx.core.config import get_config
from aptx.core.logger import get_logger, AuditAction
from aptx.core.exceptions import ToolNotFoundError, TimeoutError


class ToolStatus(str, Enum):
    """Tool execution status."""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"


@dataclass
class ToolResult:
    """
    Standardized result from tool execution.

    All tool wrappers return results in this format for
    consistent processing throughout the framework.
    """
    tool: str
    target: str
    status: ToolStatus
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = 0.0
    command: str = ""
    exit_code: int = 0
    raw_output: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    items_found: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "tool": self.tool,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "command": self.command,
            "exit_code": self.exit_code,
            "parsed_data": self.parsed_data,
            "error": self.error,
            "items_found": self.items_found,
        }

    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ToolStatus.SUCCESS


class ToolWrapper(ABC):
    """
    Abstract base class for security tool wrappers.

    Provides standardized interface for executing external tools,
    parsing output, and handling errors.
    """

    # Tool metadata (override in subclasses)
    name: str = "base"
    description: str = "Base tool wrapper"
    install_hint: str = ""
    default_timeout: int = 300  # 5 minutes

    def __init__(
        self,
        binary_path: Optional[str] = None,
        config: Optional[Dict] = None
    ):
        """
        Initialize tool wrapper.

        Args:
            binary_path: Path to tool binary (uses PATH if not specified)
            config: Tool-specific configuration
        """
        self.logger = get_logger().get_child(f"tool.{self.name}")
        self.config = config or {}

        # Get binary path from config or use default
        app_config = get_config()
        self.binary_path = (
            binary_path
            or app_config.get(f"tools.{self.name}")
            or self.name
        )

        # Verify tool is installed
        self._verified = False

    def verify_installation(self) -> bool:
        """
        Verify the tool is installed and accessible.

        Returns:
            True if tool is available

        Raises:
            ToolNotFoundError: If tool is not found
        """
        if self._verified:
            return True

        # Check if binary exists
        binary = shutil.which(self.binary_path)
        if not binary:
            raise ToolNotFoundError(
                tool_name=self.name,
                install_hint=self.install_hint
            )

        self._verified = True
        self.logger.debug(f"Tool verified: {binary}")
        return True

    def is_available(self) -> bool:
        """Check if tool is available without raising exception."""
        try:
            return self.verify_installation()
        except ToolNotFoundError:
            return False

    @abstractmethod
    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build the command line arguments for execution.

        Args:
            target: Target to scan
            options: Tool-specific options

        Returns:
            List of command line arguments
        """
        pass

    @abstractmethod
    def parse_output(
        self,
        raw_output: str,
        target: str
    ) -> Dict[str, Any]:
        """
        Parse raw tool output into structured data.

        Args:
            raw_output: Raw stdout from tool
            target: Target that was scanned

        Returns:
            Parsed data dictionary
        """
        pass

    def run(
        self,
        target: str,
        options: Optional[Dict] = None,
        timeout: Optional[int] = None,
        env: Optional[Dict] = None
    ) -> ToolResult:
        """
        Execute the tool synchronously.

        Args:
            target: Target to scan
            options: Tool-specific options
            timeout: Execution timeout in seconds
            env: Additional environment variables

        Returns:
            ToolResult with execution details
        """
        self.verify_installation()

        started_at = datetime.utcnow()
        timeout = timeout or self.default_timeout

        # Build command
        cmd = self.build_command(target, options)
        cmd_str = " ".join(cmd)

        self.logger.info(f"Executing: {cmd_str[:100]}...")
        self.logger.debug(f"Full command: {cmd_str}")

        # Setup environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        # Create temp file for output if needed
        output_file = None
        if self._uses_output_file():
            output_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                delete=False
            )
            output_file.close()
            cmd = self._inject_output_file(cmd, output_file.name)

        try:
            # Execute
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=run_env,
                cwd=tempfile.gettempdir()
            )

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            # Get output
            raw_output = process.stdout
            if output_file and Path(output_file.name).exists():
                raw_output = Path(output_file.name).read_text()

            # Parse output
            try:
                parsed_data = self.parse_output(raw_output, target)
                items_found = self._count_items(parsed_data)
            except Exception as e:
                self.logger.warning(f"Failed to parse output: {e}")
                parsed_data = {"raw": raw_output[:10000]}
                items_found = 0

            # Determine status
            if process.returncode == 0:
                status = ToolStatus.SUCCESS
            else:
                status = ToolStatus.FAILED

            result = ToolResult(
                tool=self.name,
                target=target,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                command=cmd_str,
                exit_code=process.returncode,
                raw_output=raw_output[:50000],  # Limit raw output size
                parsed_data=parsed_data,
                error=process.stderr if process.returncode != 0 else None,
                items_found=items_found
            )

            # Log audit
            self.logger.audit(
                AuditAction.TOOL_COMPLETED if status == ToolStatus.SUCCESS else AuditAction.TOOL_FAILED,
                f"{self.name} {'completed' if status == ToolStatus.SUCCESS else 'failed'}",
                target=target,
                details={
                    "command": cmd_str[:200],
                    "duration": duration,
                    "exit_code": process.returncode,
                    "items_found": items_found
                }
            )

            return result

        except subprocess.TimeoutExpired:
            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            self.logger.error(f"Tool timeout after {timeout}s")

            return ToolResult(
                tool=self.name,
                target=target,
                status=ToolStatus.TIMEOUT,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                command=cmd_str,
                error=f"Execution timed out after {timeout} seconds"
            )

        except PermissionError:
            return ToolResult(
                tool=self.name,
                target=target,
                status=ToolStatus.PERMISSION_DENIED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                command=cmd_str,
                error="Permission denied executing tool"
            )

        except Exception as e:
            self.logger.error(f"Tool execution failed: {e}")
            return ToolResult(
                tool=self.name,
                target=target,
                status=ToolStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                command=cmd_str,
                error=str(e)
            )

        finally:
            # Cleanup temp files
            if output_file and Path(output_file.name).exists():
                try:
                    Path(output_file.name).unlink()
                except Exception:
                    pass

    async def run_async(
        self,
        target: str,
        options: Optional[Dict] = None,
        timeout: Optional[int] = None
    ) -> ToolResult:
        """
        Execute the tool asynchronously.

        Args:
            target: Target to scan
            options: Tool-specific options
            timeout: Execution timeout

        Returns:
            ToolResult with execution details
        """
        self.verify_installation()

        started_at = datetime.utcnow()
        timeout = timeout or self.default_timeout

        cmd = self.build_command(target, options)
        cmd_str = " ".join(cmd)

        self.logger.info(f"Async executing: {cmd_str[:100]}...")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return ToolResult(
                    tool=self.name,
                    target=target,
                    status=ToolStatus.TIMEOUT,
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                    command=cmd_str,
                    error=f"Timeout after {timeout}s"
                )

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            raw_output = stdout.decode("utf-8", errors="replace")

            try:
                parsed_data = self.parse_output(raw_output, target)
                items_found = self._count_items(parsed_data)
            except Exception as e:
                parsed_data = {"raw": raw_output[:10000]}
                items_found = 0

            status = ToolStatus.SUCCESS if process.returncode == 0 else ToolStatus.FAILED

            return ToolResult(
                tool=self.name,
                target=target,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                command=cmd_str,
                exit_code=process.returncode,
                raw_output=raw_output[:50000],
                parsed_data=parsed_data,
                error=stderr.decode() if process.returncode != 0 else None,
                items_found=items_found
            )

        except Exception as e:
            return ToolResult(
                tool=self.name,
                target=target,
                status=ToolStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                command=cmd_str,
                error=str(e)
            )

    def _uses_output_file(self) -> bool:
        """Override if tool writes to file instead of stdout."""
        return False

    def _inject_output_file(self, cmd: List[str], path: str) -> List[str]:
        """Override to add output file argument."""
        return cmd

    def _count_items(self, parsed_data: Dict) -> int:
        """Count items in parsed output."""
        # Try common keys
        for key in ["hosts", "subdomains", "urls", "findings", "results", "items"]:
            if key in parsed_data and isinstance(parsed_data[key], list):
                return len(parsed_data[key])
        return 0

    def get_version(self) -> Optional[str]:
        """Get the tool version."""
        try:
            result = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip().split("\n")[0]
        except Exception:
            return None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(binary='{self.binary_path}')"
