"""
APT-X CVSS Calculator
=====================

CVSS 3.1 score calculation.
"""

from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CVSSMetrics:
    """CVSS 3.1 Base Metrics."""
    attack_vector: str = "N"  # N, A, L, P
    attack_complexity: str = "L"  # L, H
    privileges_required: str = "N"  # N, L, H
    user_interaction: str = "N"  # N, R
    scope: str = "U"  # U, C
    confidentiality: str = "N"  # N, L, H
    integrity: str = "N"  # N, L, H
    availability: str = "N"  # N, L, H


class CVSSCalculator:
    """CVSS 3.1 Score Calculator."""

    # Metric values
    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    PR_VALUES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_VALUES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_VALUES = {"N": 0.85, "R": 0.62}
    CIA_VALUES = {"N": 0, "L": 0.22, "H": 0.56}

    def calculate(self, metrics: CVSSMetrics) -> Tuple[float, str, str]:
        """
        Calculate CVSS score.

        Returns:
            Tuple of (score, severity, vector_string)
        """
        # Impact Sub-Score
        isc_base = 1 - (
            (1 - self.CIA_VALUES[metrics.confidentiality]) *
            (1 - self.CIA_VALUES[metrics.integrity]) *
            (1 - self.CIA_VALUES[metrics.availability])
        )

        if metrics.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)

        # Exploitability Sub-Score
        pr_values = self.PR_VALUES_CHANGED if metrics.scope == "C" else self.PR_VALUES_UNCHANGED
        exploitability = (
            8.22 *
            self.AV_VALUES[metrics.attack_vector] *
            self.AC_VALUES[metrics.attack_complexity] *
            pr_values[metrics.privileges_required] *
            self.UI_VALUES[metrics.user_interaction]
        )

        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif metrics.scope == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round up to one decimal
        base_score = round(base_score * 10) / 10

        # Determine severity
        severity = self._get_severity(base_score)

        # Build vector string
        vector = self._build_vector(metrics)

        return base_score, severity, vector

    def _get_severity(self, score: float) -> str:
        """Get severity rating from score."""
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"

    def _build_vector(self, metrics: CVSSMetrics) -> str:
        """Build CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{metrics.attack_vector}/AC:{metrics.attack_complexity}/"
            f"PR:{metrics.privileges_required}/UI:{metrics.user_interaction}/"
            f"S:{metrics.scope}/C:{metrics.confidentiality}/"
            f"I:{metrics.integrity}/A:{metrics.availability}"
        )

    def get_score_for_vuln_type(self, vuln_type: str) -> Tuple[float, str, str]:
        """Get typical CVSS score for a vulnerability type."""
        # Default metrics for common vulnerability types
        vuln_metrics = {
            "sqli": CVSSMetrics(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="U", confidentiality="H", integrity="H", availability="H"
            ),
            "xss": CVSSMetrics(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="C", confidentiality="L", integrity="L", availability="N"
            ),
            "command_injection": CVSSMetrics(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="U", confidentiality="H", integrity="H", availability="H"
            ),
            "ssrf": CVSSMetrics(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="N",
                scope="C", confidentiality="H", integrity="L", availability="N"
            ),
            "idor": CVSSMetrics(
                attack_vector="N", attack_complexity="L",
                privileges_required="L", user_interaction="N",
                scope="U", confidentiality="H", integrity="L", availability="N"
            ),
            "open_redirect": CVSSMetrics(
                attack_vector="N", attack_complexity="L",
                privileges_required="N", user_interaction="R",
                scope="C", confidentiality="L", integrity="L", availability="N"
            ),
        }

        metrics = vuln_metrics.get(vuln_type.lower(), CVSSMetrics())
        return self.calculate(metrics)
