"""
APT-X Intelligence Engine
=========================

Central coordinator for intelligence data processing and usage.
"""

from typing import Dict, List, Optional, Any
from pathlib import Path

from aptx.core.database import get_database
from aptx.core.logger import get_logger
from aptx.intelligence.classifier import DataClassifier, ClassificationResult


class IntelligenceEngine:
    """
    Central intelligence engine for APT-X.

    Coordinates data ingestion, classification, storage, and retrieval
    for improving detection capabilities.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = get_logger().get_child("intelligence")
        self.db = get_database()
        self.classifier = DataClassifier()

    def ingest(
        self,
        content: str,
        source: str,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Ingest and classify new data.

        Args:
            content: Data content
            source: Source identifier
            context: Additional context

        Returns:
            Ingestion result with classification
        """
        context = context or {}
        context["source"] = source

        # Classify the content
        classification = self.classifier.classify(content, context)

        # Store in database
        intel = self.db.add_intelligence(
            data_type=classification.data_type.value,
            content=content,
            category=classification.category.value,
            source=source,
            confidence=classification.confidence,
            usage_stage=classification.usage_stage,
            tags=classification.tags,
            metadata=context
        )

        self.logger.info(
            f"Ingested {classification.data_type.value} data: {classification.category.value}"
        )

        return {
            "id": intel.get("id"),
            "classification": {
                "data_type": classification.data_type.value,
                "category": classification.category.value,
                "confidence": classification.confidence,
                "tags": classification.tags,
            },
            "stored": True
        }

    def get_payloads(
        self,
        category: str,
        limit: int = 100,
        min_effectiveness: float = 0.0
    ) -> List[str]:
        """
        Get payloads for a vulnerability category.

        Args:
            category: Vulnerability category
            limit: Maximum payloads to return
            min_effectiveness: Minimum effectiveness score

        Returns:
            List of payload strings
        """
        intel_items = self.db.get_intelligence(
            data_type="payload",
            category=category,
            limit=limit
        )

        payloads = []
        for item in intel_items:
            if item.get("effectiveness_score", 0) >= min_effectiveness:
                payloads.append(item.get("content", ""))

        return payloads

    def get_wordlist(self, purpose: str, limit: int = 1000) -> List[str]:
        """Get wordlist items for a specific purpose."""
        intel_items = self.db.get_intelligence(
            data_type="wordlist",
            limit=limit
        )

        return [item.get("content", "").strip() for item in intel_items]

    def record_feedback(
        self,
        intel_id: str,
        successful: bool,
        finding_id: Optional[str] = None
    ) -> None:
        """Record feedback on intelligence data usage."""
        self.db.update_intelligence_effectiveness(intel_id, successful)
        self.logger.debug(f"Recorded feedback for {intel_id}: success={successful}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get intelligence engine statistics."""
        return {
            "total_items": len(self.db.get_intelligence(limit=10000)),
            "by_type": {},  # Would need count queries
            "by_category": {},
        }
