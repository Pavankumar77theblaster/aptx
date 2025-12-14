"""
APT-X Subdomain Enumeration
===========================

Subdomain enumeration using multiple tools and techniques.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from aptx.recon.base import ReconModule, ReconResult, ReconType, ReconPipelineStage
from aptx.core.pipeline import PipelineContext, StageResult, StageStatus
from aptx.tools.amass import AmassWrapper
from aptx.tools.subfinder import SubfinderWrapper


class SubdomainEnumerator(ReconModule):
    """
    Subdomain enumeration module.

    Uses Amass and Subfinder for comprehensive subdomain discovery.
    """

    recon_type = ReconType.SUBDOMAIN
    name = "subdomain"
    description = "Enumerate subdomains using multiple tools"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Initialize tools
        self.tools = {
            "amass": AmassWrapper(),
            "subfinder": SubfinderWrapper(),
        }

        # Check tool availability
        self.available_tools = []
        for name, tool in self.tools.items():
            if tool.is_available():
                self.available_tools.append(name)
            else:
                self.logger.warning(f"Tool not available: {name}")

    async def execute(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> ReconResult:
        """
        Enumerate subdomains for target domain.

        Args:
            target: Target domain
            options: Options including:
                - tools: List of tools to use (default: all available)
                - passive_only: Only use passive sources
                - recursive: Enable recursive enumeration
                - timeout: Per-tool timeout

        Returns:
            ReconResult with discovered subdomains
        """
        started = datetime.utcnow()
        options = options or {}

        # Validate target
        if not self.validate_target(target):
            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=False,
                started_at=started,
                completed_at=datetime.utcnow(),
                error="Target not in scope"
            )

        # Determine which tools to use
        tools_to_use = options.get("tools", self.available_tools)
        tools_to_use = [t for t in tools_to_use if t in self.available_tools]

        if not tools_to_use:
            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=False,
                started_at=started,
                completed_at=datetime.utcnow(),
                error="No enumeration tools available"
            )

        self.logger.info(f"Enumerating subdomains for {target} using {tools_to_use}")

        # Collect results from all tools
        all_subdomains: Set[str] = set()
        sources: Dict[str, List[str]] = {}
        tool_results: Dict[str, Dict] = {}

        # Run tools
        for tool_name in tools_to_use:
            await self.rate_limit(target)

            try:
                tool = self.tools[tool_name]
                tool_options = self._get_tool_options(tool_name, options)

                # Run in thread pool to avoid blocking
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: tool.run(target, tool_options)
                )

                if result.success:
                    # Extract subdomains
                    subdomains = self._extract_subdomains(result.parsed_data)

                    # Filter by scope
                    subdomains = self.filter_in_scope(list(subdomains))

                    all_subdomains.update(subdomains)
                    sources[tool_name] = subdomains

                    tool_results[tool_name] = {
                        "success": True,
                        "count": len(subdomains),
                        "duration": result.duration_seconds
                    }

                    self.logger.info(
                        f"{tool_name} found {len(subdomains)} subdomains"
                    )
                else:
                    tool_results[tool_name] = {
                        "success": False,
                        "error": result.error
                    }
                    self.logger.warning(f"{tool_name} failed: {result.error}")

            except Exception as e:
                self.logger.error(f"Error running {tool_name}: {e}")
                tool_results[tool_name] = {
                    "success": False,
                    "error": str(e)
                }

        completed = datetime.utcnow()

        # Build result
        result_data = {
            "subdomains": sorted(list(all_subdomains)),
            "total": len(all_subdomains),
            "by_source": {k: len(v) for k, v in sources.items()},
            "tool_results": tool_results,
            "unique_by_tool": {},
        }

        # Find unique per tool
        for tool_name, tool_subs in sources.items():
            others = set()
            for other_name, other_subs in sources.items():
                if other_name != tool_name:
                    others.update(other_subs)
            unique = set(tool_subs) - others
            result_data["unique_by_tool"][tool_name] = len(unique)

        return ReconResult(
            recon_type=self.recon_type,
            target=target,
            success=True,
            started_at=started,
            completed_at=completed,
            duration_seconds=(completed - started).total_seconds(),
            data=result_data,
            items_found=len(all_subdomains)
        )

    def _get_tool_options(
        self,
        tool_name: str,
        options: Dict
    ) -> Dict:
        """Get tool-specific options."""
        tool_options = {}

        if tool_name == "amass":
            if options.get("passive_only", True):
                tool_options["mode"] = "passive"
            else:
                tool_options["mode"] = "active"
            if "timeout" in options:
                tool_options["timeout"] = options["timeout"]

        elif tool_name == "subfinder":
            if options.get("recursive", False):
                tool_options["recursive"] = True
            if options.get("all_sources", False):
                tool_options["all_sources"] = True

        return tool_options

    def _extract_subdomains(self, parsed_data: Dict) -> Set[str]:
        """Extract subdomain list from parsed tool output."""
        subdomains = set()

        # Handle different output formats
        if "subdomains" in parsed_data:
            for item in parsed_data["subdomains"]:
                if isinstance(item, dict):
                    subdomain = item.get("subdomain", "")
                else:
                    subdomain = str(item)
                if subdomain:
                    subdomains.add(subdomain.lower().strip())

        return subdomains


class SubdomainEnumStage(ReconPipelineStage):
    """Pipeline stage for subdomain enumeration."""

    name = "subdomain_enum"
    description = "Enumerate subdomains using Amass and Subfinder"
    requires = ["target_intake", "scope_validation"]
    produces = ["subdomains"]
    module_class = SubdomainEnumerator

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute subdomain enumeration stage."""
        started = datetime.utcnow()

        try:
            module = self._create_module(context)

            # Get options from config
            options = {
                "passive_only": context.safe_mode,
                "tools": context.config.get("recon", {}).get("subdomain", {}).get(
                    "tools", ["amass", "subfinder"]
                ),
            }

            result = await module.execute(context.target, options)

            if result.success:
                # Add subdomains to context
                for subdomain in result.data.get("subdomains", []):
                    context.add_subdomain(subdomain)

                self.logger.info(
                    f"Found {result.items_found} subdomains for {context.target}"
                )

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED if result.success else StageStatus.FAILED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data=result.data,
                findings_count=result.items_found,
                error=result.error
            )

        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    def should_skip(self, context: PipelineContext) -> bool:
        """Skip if target is an IP address."""
        import re
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        return bool(re.match(ip_pattern, context.target))
