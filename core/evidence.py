"""
Evidence collection engine for Watchtower.

This module collects multiple independent pieces of evidence for each URL,
following the model: Discovery → Enrichment → Evidence → Correlation → Risk Score → Verdict

Evidence categories:
- Identity: domain, brand impersonation, typosquatting
- Infrastructure: DNS, IP, ASN, hosting, certificates
- Content: page text, forms, payment requests, credentials
- Reputation: threat intel feeds, previous reports
- Campaign: related infrastructure, shared artifacts
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _now() -> str:
    """Current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceRecord:
    """
    Complete evidence record for a single URL.
    
    This is the core data structure that replaces simple keyword scoring.
    Each field represents an independent piece of evidence that can be
    correlated with others to build confidence in a verdict.
    """
    
    # === IDENTITY EVIDENCE ===
    url: str
    domain: str = ""
    registrable_domain: str = ""
    
    # Brand impersonation signals
    brand_impersonation_score: int = 0
    brand_matched: str = ""
    typosquatting_detected: bool = False
    lookalike_domain: bool = False
    fake_subdomain: bool = False
    misleading_url_pattern: bool = False
    
    # === INFRASTRUCTURE EVIDENCE ===
    domain_age_days: Optional[int] = None
    registration_info: dict[str, Any] = field(default_factory=dict)
    
    # DNS records
    dns_records: dict[str, Any] = field(default_factory=dict)
    
    # Network information
    ip_address: str = ""
    asn: str = ""
    asn_name: str = ""
    hosting_provider: str = ""
    country: str = ""
    nameservers: list[str] = field(default_factory=list)
    
    # TLS certificate
    tls_certificate: dict[str, Any] = field(default_factory=dict)
    certificate_age_days: Optional[int] = None
    certificate_issuer: str = ""
    ct_logs: list[dict[str, Any]] = field(default_factory=list)
    
    # === CONTENT EVIDENCE ===
    http_status: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    page_title: str = ""
    page_text: str = ""
    
    # Form detection
    has_login_form: bool = False
    has_password_field: bool = False
    has_phone_field: bool = False
    has_payment_form: bool = False
    
    # Payment/credential extraction
    payment_references: list[str] = field(default_factory=list)
    mobile_money_numbers: list[str] = field(default_factory=list)
    whatsapp_links: list[str] = field(default_factory=list)
    telegram_links: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    social_media_links: list[str] = field(default_factory=list)
    
    # Content fingerprints
    html_hash: str = ""
    dom_fingerprint: str = ""
    screenshot_hash: str = ""
    favicon_hash: str = ""
    
    # === REPUTATION EVIDENCE ===
    phishtank_match: bool = False
    openphish_match: bool = False
    urlhaus_match: bool = False
    threatfox_match: bool = False
    spamhaus_drop_match: bool = False
    greynoise_classification: str = ""
    
    # Watchtower history
    previous_reports: int = 0
    first_seen: str = ""
    last_seen: str = ""
    
    # === CAMPAIGN EVIDENCE ===
    related_domains: list[str] = field(default_factory=list)
    shared_payment_numbers: list[str] = field(default_factory=list)
    shared_emails: list[str] = field(default_factory=list)
    shared_telegram: list[str] = field(default_factory=list)
    shared_whatsapp: list[str] = field(default_factory=list)
    shared_page_fingerprint: bool = False
    shared_analytics_id: str = ""
    shared_infrastructure: bool = False
    
    # === METADATA ===
    discovered_at: str = field(default_factory=_now)
    enriched_at: str = ""
    source: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert evidence record to dictionary for storage/serialization."""
        from dataclasses import asdict
        return asdict(self)
    
    def add_evidence(self, category: str, key: str, value: Any, weight: int = 0) -> None:
        """
        Add a piece of evidence with optional weight.
        
        Args:
            category: Evidence category (identity, infrastructure, content, reputation, campaign)
            key: Specific evidence type
            value: Evidence value
            weight: Optional weight for scoring (used in risk calculation)
        """
        attr_name = f"{key}"
        if hasattr(self, attr_name):
            setattr(self, attr_name, value)
        else:
            # Store in appropriate category dict if exists
            category_attr = f"{category}_evidence"
            if hasattr(self, category_attr):
                getattr(self, category_attr)[key] = value


@dataclass
class Verdict:
    """
    Final verdict based on collected evidence.
    
    Replaces simple numeric scoring with categorical assessment
    and explainable reasoning.
    """
    
    VERDICT_CATEGORIES = [
        "CONFIRMED_MALICIOUS",
        "HIGH_RISK", 
        "SUSPICIOUS",
        "LOW_RISK",
        "VERIFIED_OFFICIAL",
        "UNKNOWN"
    ]
    
    category: str = "UNKNOWN"
    confidence: float = 0.0
    risk_score: int = 0
    
    # Explainable evidence breakdown
    identity_risk: int = 0
    infrastructure_risk: int = 0
    content_risk: int = 0
    reputation_risk: int = 0
    campaign_risk: int = 0
    
    # Reasoning
    reasons: list[str] = field(default_factory=list)
    evidence_summary: dict[str, Any] = field(default_factory=dict)
    
    def explain(self) -> str:
        """Generate human-readable explanation of verdict."""
        if not self.reasons:
            return f"Verdict: {self.category} (Risk: {self.risk_score}/100)"
        
        explanation = [f"**Verdict: {self.category}** (Risk Score: {self.risk_score}/100)"]
        explanation.append("")
        explanation.append("**Why this verdict was reached:**")
        
        for reason in self.reasons:
            explanation.append(f"- {reason}")
        
        if self.evidence_summary:
            explanation.append("")
            explanation.append("**Evidence breakdown:**")
            for category, score in self.evidence_summary.items():
                if score > 0:
                    explanation.append(f"- {category.replace('_', ' ').title()}: +{score}")
        
        return "\n".join(explanation)


class EvidenceCollector:
    """
    Collects and aggregates evidence for URL analysis.
    
    This is the central engine that coordinates evidence gathering
    from multiple sources and produces verdicts.
    """
    
    def __init__(self, brands: dict[str, Any], config: dict[str, Any]):
        """
        Initialize evidence collector.
        
        Args:
            brands: Dictionary of brand configurations with official domains
            config: System configuration
        """
        self.brands = brands
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def create_record(self, url: str, source: str = "") -> EvidenceRecord:
        """Create a new evidence record for a URL."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else ""
        
        record = EvidenceRecord(
            url=url,
            domain=domain,
            source=source
        )
        
        # Compute registrable domain
        record.registrable_domain = self._get_registrable_domain(domain)
        
        return record
    
    def _get_registrable_domain(self, host: str) -> str:
        """
        Extract registrable domain (eTLD+1) from hostname.
        
        Handles common two-part ccTLDs in East Africa.
        """
        host = host.lower().strip().split(":")[0]
        host = host.removeprefix("www.")
        
        parts = host.split(".")
        if len(parts) >= 3 and parts[-2] in {"co", "or", "ac", "go", "ne", "com"}:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    
    def compute_verdict(self, record: EvidenceRecord) -> Verdict:
        """
        Compute verdict based on collected evidence.
        
        Uses multi-factor risk scoring across evidence categories.
        """
        verdict = Verdict()
        
        # Calculate risk scores per category
        verdict.identity_risk = self._score_identity_risk(record)
        verdict.infrastructure_risk = self._score_infrastructure_risk(record)
        verdict.content_risk = self._score_content_risk(record)
        verdict.reputation_risk = self._score_reputation_risk(record)
        verdict.campaign_risk = self._score_campaign_risk(record)
        
        # Total risk score (weighted average)
        weights = {
            "identity": 0.20,
            "infrastructure": 0.20,
            "content": 0.25,
            "reputation": 0.25,
            "campaign": 0.10
        }
        
        total = (
            verdict.identity_risk * weights["identity"] +
            verdict.infrastructure_risk * weights["infrastructure"] +
            verdict.content_risk * weights["content"] +
            verdict.reputation_risk * weights["reputation"] +
            verdict.campaign_risk * weights["campaign"]
        )
        
        verdict.risk_score = min(100, max(0, int(total)))
        
        # Determine verdict category
        verdict.category = self._categorize_verdict(verdict, record)
        
        # Generate reasons
        verdict.reasons = self._generate_reasons(record, verdict)
        
        # Build evidence summary
        verdict.evidence_summary = {
            "identity_risk": verdict.identity_risk,
            "infrastructure_risk": verdict.infrastructure_risk,
            "content_risk": verdict.content_risk,
            "reputation_risk": verdict.reputation_risk,
            "campaign_risk": verdict.campaign_risk
        }
        
        # Confidence based on evidence completeness
        verdict.confidence = self._compute_confidence(record)
        
        return verdict
    
    def _score_identity_risk(self, record: EvidenceRecord) -> int:
        """Score identity-related risk (0-30)."""
        score = 0
        
        if record.brand_impersonation_score >= 85:
            score += 25
        elif record.brand_impersonation_score >= 70:
            score += 15
        elif record.brand_impersonation_score >= 50:
            score += 10
        
        if record.typosquatting_detected:
            score += 20
        
        if record.lookalike_domain:
            score += 15
        
        if record.fake_subdomain:
            score += 10
        
        if record.misleading_url_pattern:
            score += 10
        
        return min(30, score)
    
    def _score_infrastructure_risk(self, record: EvidenceRecord) -> int:
        """Score infrastructure-related risk (0-25)."""
        score = 0
        
        # CRITICAL: Brand impersonation on free hosting is an automatic high-risk signal
        # This cannot be averaged out by other factors
        free_hosts = ["vercel.app", "netlify.app", "firebaseapp.com", "web.app", "pages.dev", 
                      "herokuapp.com", "blogspot.com", "wordpress.com", "wixsite.com"]
        is_free_hosting = any(fh in record.domain for fh in free_hosts)
        
        if is_free_hosting and record.brand_impersonation_score >= 50:
            # CRITICAL TRIGGER: Free hosting + brand mention = likely scam
            return 25  # Maximum score for this category
        
        # Newly registered domain
        if record.domain_age_days is not None and record.domain_age_days < 30:
            score += 15
        
        # Recently issued certificate
        if record.certificate_age_days is not None and record.certificate_age_days < 7:
            score += 10
        
        # Free hosting alone (without brand) is still suspicious
        if is_free_hosting:
            score += 15
        
        # Malicious IP history (from GreyNoise)
        if record.greynoise_classification in ["malicious", "attacker"]:
            score += 20
        
        # Infrastructure reuse
        if record.shared_infrastructure:
            score += 20
        
        return min(25, score)
    
    def _score_content_risk(self, record: EvidenceRecord) -> int:
        """Score content-related risk (0-30)."""
        score = 0
        
        if record.has_login_form or record.has_password_field:
            score += 20
        
        if record.has_payment_form:
            score += 25
        
        # Payment/credential requests
        if record.payment_references:
            score += 20
        
        if record.mobile_money_numbers:
            score += 15
        
        # Check for suspicious keywords in page text
        text_lower = (record.page_title + " " + record.page_text).lower()
        
        suspicious_patterns = [
            (r"send.*pin", 25),
            (r"share.*pin", 25),
            (r"enter.*pin", 20),
            (r"otp", 25),
            (r"one.?time.?password", 20),
            (r"processing.?fee", 20),
            (r"activation.?fee", 20),
            (r"pay.*to.*unlock", 25),
            (r"pay.*to.*activate", 25),
        ]
        
        for pattern, points in suspicious_patterns:
            if re.search(pattern, text_lower):
                score += points
        
        return min(30, score)
    
    def _score_reputation_risk(self, record: EvidenceRecord) -> int:
        """Score reputation-related risk (0-40)."""
        score = 0
        
        if record.phishtank_match:
            score += 35
        
        if record.openphish_match:
            score += 35
        
        if record.urlhaus_match:
            score += 30
        
        if record.threatfox_match:
            score += 30
        
        if record.spamhaus_drop_match:
            score += 40
        
        if record.previous_reports > 0:
            score += min(25, record.previous_reports * 10)
        
        return min(40, score)
    
    def _score_campaign_risk(self, record: EvidenceRecord) -> int:
        """Score campaign-related risk (0-25)."""
        score = 0
        
        if record.related_domains:
            score += 15
        
        if record.shared_payment_numbers:
            score += 20
        
        if record.shared_emails:
            score += 15
        
        if record.shared_telegram:
            score += 15
        
        if record.shared_whatsapp:
            score += 15
        
        if record.shared_page_fingerprint:
            score += 20
        
        if record.shared_analytics_id:
            score += 10
        
        if record.shared_infrastructure:
            score += 15
        
        return min(25, score)
    
    def _categorize_verdict(self, verdict: Verdict, record: EvidenceRecord) -> str:
        """Determine verdict category based on scores and evidence."""
        
        # Check for verified official domain
        if self._is_verified_official(record):
            return "VERIFIED_OFFICIAL"
        
        # CRITICAL: Brand impersonation on free hosting = automatic HIGH_RISK
        free_hosts = ["vercel.app", "netlify.app", "firebaseapp.com", "web.app", "pages.dev",
                      "herokuapp.com", "blogspot.com", "wordpress.com", "wixsite.com"]
        is_free_hosting = any(fh in record.domain for fh in free_hosts)
        
        if is_free_hosting and record.brand_impersonation_score >= 50:
            # This is a critical pattern that cannot be downgraded
            return "HIGH_RISK"
        
        # Confirmed malicious: strong reputation signals
        if verdict.reputation_risk >= 35:
            return "CONFIRMED_MALICIOUS"
        
        # High risk: multiple strong indicators OR brand impersonation on suspicious infrastructure
        if verdict.risk_score >= 70 or (record.brand_impersonation_score >= 70 and is_free_hosting):
            return "HIGH_RISK"
        
        # Suspicious: some concerning indicators OR any brand impersonation
        if verdict.risk_score >= 40 or record.brand_impersonation_score >= 50:
            return "SUSPICIOUS"
        
        # Low risk: limited evidence
        if verdict.risk_score >= 20:
            return "LOW_RISK"
        
        # Unknown: insufficient evidence
        return "UNKNOWN"
    
    def _is_verified_official(self, record: EvidenceRecord) -> bool:
        """Check if domain is verified as official."""
        for brand_name, brand_config in self.brands.items():
            official_domains = brand_config.get("official_domains", [])
            for official in official_domains:
                if record.domain == official or record.domain.endswith("." + official):
                    return True
        return False
    
    def _generate_reasons(self, record: EvidenceRecord, verdict: Verdict) -> list[str]:
        """Generate human-readable reasons for verdict."""
        reasons = []
        
        if record.brand_impersonation_score >= 70:
            reasons.append(f"Brand impersonation detected (score: {record.brand_impersonation_score})")
        
        if record.typosquatting_detected:
            reasons.append("Typosquatting pattern detected")
        
        if record.domain_age_days is not None and record.domain_age_days < 30:
            reasons.append(f"Newly registered domain ({record.domain_age_days} days old)")
        
        if record.has_payment_form:
            reasons.append("Payment form detected on suspicious domain")
        
        if record.phishtank_match:
            reasons.append("Matched PhishTank phishing database")
        
        if record.openphish_match:
            reasons.append("Matched OpenPhish database")
        
        if record.urlhaus_match:
            reasons.append("Matched URLhaus malware database")
        
        if record.shared_infrastructure:
            reasons.append("Shares infrastructure with known malicious sites")
        
        if self._is_verified_official(record):
            reasons.append("Verified official domain")
        
        return reasons
    
    def _compute_confidence(self, record: EvidenceRecord) -> float:
        """
        Compute confidence level based on evidence completeness.
        
        Returns value between 0.0 (no evidence) and 1.0 (complete evidence).
        """
        evidence_fields = [
            "domain_age_days",
            "ip_address",
            "asn",
            "tls_certificate",
            "page_text",
            "has_login_form",
            "has_payment_form",
        ]
        
        present = sum(1 for field in evidence_fields if getattr(record, field, None))
        
        # Also consider reputation matches
        reputation_signals = [
            record.phishtank_match,
            record.openphish_match,
            record.urlhaus_match,
            record.threatfox_match,
        ]
        
        reputation_present = sum(1 for signal in reputation_signals if signal)
        
        # Normalize to 0-1 range
        base_confidence = present / len(evidence_fields)
        reputation_bonus = min(0.3, reputation_present * 0.15)
        
        return min(1.0, base_confidence * 0.7 + reputation_bonus)


# Export main classes
__all__ = ["EvidenceRecord", "Verdict", "EvidenceCollector"]
