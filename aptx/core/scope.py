"""
APT-X Scope Validation
======================

Scope enforcement module for validating targets against allowlists
and ensuring penetration testing stays within authorized boundaries.
"""

import re
import socket
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse
from dataclasses import dataclass, field

import tldextract
import yaml

from aptx.core.exceptions import ScopeViolationError, ConfigurationError
from aptx.core.logger import get_logger, AuditAction


@dataclass
class ScopeRule:
    """Represents a scope rule for validation."""
    type: str  # domain, ip, cidr, wildcard
    value: str
    original: str


@dataclass
class ScopeConfig:
    """Scope configuration."""
    name: str = "default"
    description: str = ""
    strict_mode: bool = True
    block_private_ips: bool = True
    block_localhost: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    allowed_cidrs: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    blocked_ips: List[str] = field(default_factory=list)
    blocked_paths: List[str] = field(default_factory=list)


class ScopeValidator:
    """
    Validates targets against defined scope boundaries.

    Ensures penetration testing activities stay within authorized
    scope by validating domains, IPs, and URLs against allowlists.
    """

    # Private IP ranges (RFC 1918, etc.)
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),  # Link-local
        ipaddress.ip_network("::1/128"),  # IPv6 loopback
        ipaddress.ip_network("fc00::/7"),  # IPv6 private
        ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ]

    def __init__(
        self,
        config: Optional[ScopeConfig] = None,
        config_file: Optional[Union[str, Path]] = None
    ):
        """
        Initialize scope validator.

        Args:
            config: ScopeConfig object
            config_file: Path to YAML scope configuration file
        """
        self.logger = get_logger().get_child("scope")
        self.config: ScopeConfig = config or ScopeConfig()

        # Initialize rule containers first
        self._allowed_domains: Set[str] = set()
        self._allowed_wildcards: List[str] = []
        self._allowed_ips: Set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self._allowed_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._blocked_domains: Set[str] = set()
        self._blocked_ips: Set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self._blocked_paths: List[re.Pattern] = []

        # Load from file if provided
        if config_file:
            self.load_from_file(config_file)
        else:
            # Compile rules from config
            self._compile_rules()

    def load_from_file(self, path: Union[str, Path]) -> None:
        """
        Load scope configuration from YAML file.

        Args:
            path: Path to YAML configuration file

        Raises:
            ConfigurationError: If file cannot be loaded
        """
        path = Path(path)
        if not path.exists():
            raise ConfigurationError(f"Scope file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            self.config = ScopeConfig(
                name=data.get("name", "default"),
                description=data.get("description", ""),
                strict_mode=data.get("strict_mode", True),
                block_private_ips=data.get("block_private_ips", True),
                block_localhost=data.get("block_localhost", True),
                allowed_domains=data.get("allowed_domains", []),
                allowed_ips=data.get("allowed_ips", []),
                allowed_cidrs=data.get("allowed_cidrs", []),
                blocked_domains=data.get("blocked_domains", []),
                blocked_ips=data.get("blocked_ips", []),
                blocked_paths=data.get("blocked_paths", []),
            )

            self._compile_rules()
            self.logger.info(f"Loaded scope configuration from {path}")
            self.logger.audit(
                AuditAction.SCOPE_LOADED,
                f"Loaded scope: {self.config.name}",
                details={"file": str(path), "domains": len(self.config.allowed_domains)}
            )

        except yaml.YAMLError as e:
            raise ConfigurationError(f"Failed to parse scope YAML: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load scope file: {e}")

    def _compile_rules(self) -> None:
        """Compile scope rules for efficient validation."""
        # Clear existing
        self._allowed_domains.clear()
        self._allowed_wildcards.clear()
        self._allowed_ips.clear()
        self._allowed_networks.clear()
        self._blocked_domains.clear()
        self._blocked_ips.clear()
        self._blocked_paths.clear()

        # Process allowed domains
        for domain in self.config.allowed_domains:
            domain = domain.lower().strip()
            if domain.startswith("*."):
                self._allowed_wildcards.append(domain[2:])
            else:
                self._allowed_domains.add(domain)

        # Process allowed IPs
        for ip in self.config.allowed_ips:
            try:
                self._allowed_ips.add(ipaddress.ip_address(ip))
            except ValueError:
                self.logger.warning(f"Invalid IP in scope: {ip}")

        # Process allowed CIDRs
        for cidr in self.config.allowed_cidrs:
            try:
                self._allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                self.logger.warning(f"Invalid CIDR in scope: {cidr}")

        # Process blocked domains
        for domain in self.config.blocked_domains:
            self._blocked_domains.add(domain.lower().strip())

        # Process blocked IPs
        for ip in self.config.blocked_ips:
            try:
                self._blocked_ips.add(ipaddress.ip_address(ip))
            except ValueError:
                self.logger.warning(f"Invalid blocked IP: {ip}")

        # Process blocked paths (compile as regex)
        for path_pattern in self.config.blocked_paths:
            try:
                self._blocked_paths.append(re.compile(path_pattern, re.IGNORECASE))
            except re.error:
                self.logger.warning(f"Invalid path pattern: {path_pattern}")

    def add_target(
        self,
        target: str,
        target_type: str = "auto"
    ) -> None:
        """
        Add a target to the allowed scope.

        Args:
            target: Domain, IP, or CIDR to add
            target_type: Type hint (domain, ip, cidr, auto)
        """
        target = target.strip()

        if target_type == "auto":
            target_type = self._detect_target_type(target)

        if target_type == "domain":
            if target.startswith("*."):
                self._allowed_wildcards.append(target[2:].lower())
            else:
                self._allowed_domains.add(target.lower())
                self.config.allowed_domains.append(target)
        elif target_type == "ip":
            try:
                ip = ipaddress.ip_address(target)
                self._allowed_ips.add(ip)
                self.config.allowed_ips.append(target)
            except ValueError:
                raise ScopeViolationError(target, "Invalid IP address")
        elif target_type == "cidr":
            try:
                network = ipaddress.ip_network(target, strict=False)
                self._allowed_networks.append(network)
                self.config.allowed_cidrs.append(target)
            except ValueError:
                raise ScopeViolationError(target, "Invalid CIDR notation")

        self.logger.info(f"Added {target_type} to scope: {target}")

    def _detect_target_type(self, target: str) -> str:
        """Detect the type of a target."""
        # Check for CIDR
        if "/" in target:
            return "cidr"

        # Check for IP
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass

        # Assume domain
        return "domain"

    def validate(
        self,
        target: str,
        resolve_dns: bool = False,
        check_path: bool = True
    ) -> Tuple[bool, str]:
        """
        Validate a target against the scope.

        Args:
            target: URL, domain, or IP to validate
            resolve_dns: Also validate resolved IP addresses
            check_path: Check URL paths against blocked patterns

        Returns:
            Tuple of (is_valid, reason)
        """
        original_target = target

        # Parse URL if provided
        url_parts = None
        if "://" in target:
            url_parts = urlparse(target)
            target = url_parts.netloc
            if ":" in target:
                target = target.split(":")[0]

        # Check blocked paths
        if check_path and url_parts and url_parts.path:
            for pattern in self._blocked_paths:
                if pattern.search(url_parts.path):
                    reason = f"Path matches blocked pattern: {pattern.pattern}"
                    self._log_violation(original_target, reason)
                    return False, reason

        # Determine if target is IP or domain
        is_ip = False
        try:
            ip_addr = ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            ip_addr = None

        if is_ip:
            valid, reason = self._validate_ip(ip_addr)
        else:
            valid, reason = self._validate_domain(target)

            # Optionally resolve and check IP
            if valid and resolve_dns:
                try:
                    resolved_ips = socket.gethostbyname_ex(target)[2]
                    for resolved_ip in resolved_ips:
                        ip_valid, ip_reason = self._validate_ip(
                            ipaddress.ip_address(resolved_ip)
                        )
                        if not ip_valid:
                            reason = f"Resolved IP {resolved_ip}: {ip_reason}"
                            valid = False
                            break
                except socket.gaierror:
                    pass  # DNS resolution failed, but domain is valid

        if valid:
            self.logger.log_scope_check(original_target, True)
        else:
            self._log_violation(original_target, reason)

        return valid, reason

    def _validate_ip(
        self,
        ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ) -> Tuple[bool, str]:
        """Validate an IP address against scope."""
        # Check if blocked
        if ip in self._blocked_ips:
            return False, "IP is explicitly blocked"

        # Check localhost
        if self.config.block_localhost:
            if ip.is_loopback:
                return False, "Localhost is blocked"

        # Check private ranges
        if self.config.block_private_ips:
            if ip.is_private:
                return False, "Private IP ranges are blocked"

        # In strict mode, must be explicitly allowed
        if self.config.strict_mode:
            # Check exact IP
            if ip in self._allowed_ips:
                return True, "IP is in allowlist"

            # Check CIDR ranges
            for network in self._allowed_networks:
                if ip in network:
                    return True, f"IP is in allowed range {network}"

            return False, "IP not in allowed scope (strict mode)"

        # Non-strict mode: allow if not blocked
        return True, "IP is allowed (non-strict mode)"

    def _validate_domain(self, domain: str) -> Tuple[bool, str]:
        """Validate a domain against scope."""
        domain = domain.lower().strip()

        # Extract registered domain
        extracted = tldextract.extract(domain)
        registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()

        # Check if blocked
        if domain in self._blocked_domains or registered_domain in self._blocked_domains:
            return False, "Domain is explicitly blocked"

        # Check exact match
        if domain in self._allowed_domains:
            return True, "Domain is in allowlist"

        # Check registered domain match
        if registered_domain in self._allowed_domains:
            return True, "Parent domain is in allowlist"

        # Check wildcard matches
        for wildcard in self._allowed_wildcards:
            if domain.endswith(f".{wildcard}") or domain == wildcard:
                return True, f"Domain matches wildcard *.{wildcard}"

        # In strict mode, must be explicitly allowed
        if self.config.strict_mode:
            return False, "Domain not in allowed scope (strict mode)"

        return True, "Domain is allowed (non-strict mode)"

    def _log_violation(self, target: str, reason: str) -> None:
        """Log a scope violation."""
        self.logger.log_scope_check(target, False, reason)
        self.logger.warning(f"Scope violation: {target} - {reason}")

    def validate_or_raise(
        self,
        target: str,
        resolve_dns: bool = False
    ) -> None:
        """
        Validate target and raise exception if invalid.

        Args:
            target: Target to validate

        Raises:
            ScopeViolationError: If target is out of scope
        """
        valid, reason = self.validate(target, resolve_dns)
        if not valid:
            raise ScopeViolationError(target, reason)

    def is_empty(self) -> bool:
        """Check if scope has any rules defined."""
        return (
            len(self._allowed_domains) == 0
            and len(self._allowed_wildcards) == 0
            and len(self._allowed_ips) == 0
            and len(self._allowed_networks) == 0
        )

    def get_summary(self) -> Dict:
        """Get a summary of the scope configuration."""
        return {
            "name": self.config.name,
            "strict_mode": self.config.strict_mode,
            "block_private_ips": self.config.block_private_ips,
            "allowed_domains": len(self.config.allowed_domains),
            "allowed_wildcards": len(self._allowed_wildcards),
            "allowed_ips": len(self.config.allowed_ips),
            "allowed_cidrs": len(self.config.allowed_cidrs),
            "blocked_domains": len(self.config.blocked_domains),
            "blocked_paths": len(self.config.blocked_paths),
        }

    def to_yaml(self) -> str:
        """Export scope configuration to YAML string."""
        data = {
            "name": self.config.name,
            "description": self.config.description,
            "strict_mode": self.config.strict_mode,
            "block_private_ips": self.config.block_private_ips,
            "block_localhost": self.config.block_localhost,
            "allowed_domains": self.config.allowed_domains,
            "allowed_ips": self.config.allowed_ips,
            "allowed_cidrs": self.config.allowed_cidrs,
            "blocked_domains": self.config.blocked_domains,
            "blocked_ips": self.config.blocked_ips,
            "blocked_paths": self.config.blocked_paths,
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    def save_to_file(self, path: Union[str, Path]) -> None:
        """Save scope configuration to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_yaml())
        self.logger.info(f"Saved scope configuration to {path}")

    def __repr__(self) -> str:
        return (
            f"ScopeValidator(name='{self.config.name}', "
            f"domains={len(self._allowed_domains)}, "
            f"ips={len(self._allowed_ips)}, "
            f"strict={self.config.strict_mode})"
        )
