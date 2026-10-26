"""
Threat intelligence integration for Watchtower.

This module provides interfaces to external threat intelligence feeds:
- PhishTank (phishing URLs)
- OpenPhish (phishing feed)
- URLhaus (malware URLs)
- ThreatFox (IOCs)
- Spamhaus DROP (malicious networks)
- GreyNoise (IP reputation)

IMPORTANT: These are evidence sources, NOT truth. A match increases risk;
no match does NOT mean safe.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen, Request
import ssl

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Aggregates threat intelligence from multiple sources.
    
    Each source provides independent evidence that contributes to
    the overall risk assessment. No single source determines verdict.
    """
    
    def __init__(self, config: dict[str, Any]):
        """
        Initialize threat intelligence collector.
        
        Args:
            config: Configuration with API keys and settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Cache to avoid repeated lookups
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_time: dict[str, float] = {}
        self._cache_ttl = 3600  # 1 hour cache
    
    def check_url(self, url: str) -> dict[str, Any]:
        """
        Check URL against all available threat intelligence sources.
        
        Returns:
            Dictionary with match results from each source
        """
        # Check cache first
        cache_key = hashlib.sha256(url.encode()).hexdigest()[:16]
        if cache_key in self._cache:
            if time.time() - self._cache_time[cache_key] < self._cache_ttl:
                return self._cache[cache_key]
        
        result = {
            "url": url,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "phishtank": self._check_phishtank(url),
            "openphish": self._check_openphish(url),
            "urlhaus": self._check_urlhaus(url),
            "threatfox": self._check_threatfox(url),
            "spamhaus": self._check_spamhaus(url),
        }
        
        # Cache result
        self._cache[cache_key] = result
        self._cache_time[cache_key] = time.time()
        
        return result
    
    def _check_phishtank(self, url: str) -> dict[str, Any]:
        """
        Check URL against PhishTank database.
        
        PhishTank is operated by Cisco Talos and provides community-verified
        phishing URLs. Use it to answer: "Has this URL already been reported?"
        
        IMPORTANT: No match does NOT mean safe - only that PhishTank doesn't know it yet.
        """
        try:
            # PhishTank API requires API key for programmatic access
            # Community can submit via web interface
            # For now, we'll use the public feed approach
            
            # In production, you would:
            # 1. Get API key from https://www.phishtank.org/api_info.php
            # 2. Download verified phishing URLs
            # 3. Check if URL or its domain is in the list
            
            api_key = self.config.get("phishtank_api_key", "")
            
            if not api_key:
                return {
                    "matched": False,
                    "available": False,
                    "note": "PhishTank API key not configured"
                }
            
            # This legacy collector has no implemented API call. Never report
            # an integration as available merely because a key string exists.
            return {
                "matched": False,
                "available": False,
                "source": "PhishTank",
                "note": "Connector not implemented; no lookup was performed"
            }
            
        except Exception as e:
            self.logger.error(f"PhishTank check failed: {e}")
            return {"matched": False, "available": False, "error": str(e)}
    
    def _check_openphish(self, url: str) -> dict[str, Any]:
        """
        Check URL against OpenPhish database.
        
        OpenPhish provides a community feed updated every 12 hours.
        Includes metadata: hostname, path, IP, ASN, country, brand.
        
        IMPORTANT: Free feed has terms of use - check before commercial use.
        """
        try:
            # OpenPhish community feed URL
            feed_url = "https://openphish.com/feed.txt"
            
            # In production:
            # 1. Download feed periodically (every 12 hours)
            # 2. Parse and store in database
            # 3. Check URL/domain against stored entries
            
            # Feed mirroring needs an explicit terms/retention policy and local
            # cache. Until that exists, report unavailable rather than a fake
            # successful negative.
            return {
                "matched": False,
                "available": False,
                "source": "OpenPhish",
                "note": "Community-feed mirror is not configured"
            }
            
        except Exception as e:
            self.logger.error(f"OpenPhish check failed: {e}")
            return {"matched": False, "available": False, "error": str(e)}
    
    def _check_urlhaus(self, url: str) -> dict[str, Any]:
        """
        Check URL against URLhaus database.
        
        URLhaus (abuse.ch) focuses on malware distribution URLs.
        Provides API for checking URLs and downloading datasets.
        
        IMPORTANT: URLhaus is for malware, not phishing - treat as separate evidence category.
        """
        try:
            # URLhaus API endpoint
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
            
            # Prepare POST data
            post_data = f"url={urlparse(url).netloc}".encode()
            
            req = Request(
                api_url,
                data=post_data,
                headers={"User-Agent": "Watchtower/1.0"},
                method="POST"
            )
            
            # Create SSL context
            ctx = ssl.create_default_context()
            
            with urlopen(req, timeout=10, context=ctx) as response:
                data = json.loads(response.read().decode())
                
                if data.get("query_status") == "ok" and data.get("url"):
                    return {
                        "matched": True,
                        "available": True,
                        "source": "URLhaus",
                        "threat_type": "malware",
                        "details": data
                    }
            
            return {
                "matched": False,
                "available": True,
                "source": "URLhaus",
                "threat_type": "malware"
            }
            
        except Exception as e:
            self.logger.error(f"URLhaus check failed: {e}")
            return {"matched": False, "available": False, "error": str(e)}
    
    def _check_threatfox(self, url: str) -> dict[str, Any]:
        """
        Check URL/domain against ThreatFox database.
        
        ThreatFox (abuse.ch) provides IOCs with confidence scores and threat types.
        Covers domains, IPs, URLs and other indicators.
        
        Useful for correlating: domain → IP → ASN → related domains → known IOC
        """
        try:
            # ThreatFox API endpoint
            api_url = "https://threatfox-api.abuse.ch/api/v1/"
            
            # Extract domain from URL
            domain = urlparse(url).netloc
            
            # Prepare POST data for search_ioc
            post_data = json.dumps({
                "query": "search_ioc",
                "ioc": domain
            }).encode()
            
            req = Request(
                api_url,
                data=post_data,
                headers={
                    "User-Agent": "Watchtower/1.0",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            
            ctx = ssl.create_default_context()
            
            with urlopen(req, timeout=10, context=ctx) as response:
                data = json.loads(response.read().decode())
                
                if data.get("query_status") == "ok" and data.get("data"):
                    ioc_data = data["data"]
                    return {
                        "matched": True,
                        "available": True,
                        "source": "ThreatFox",
                        "threat_type": ioc_data.get("threat_type", "unknown"),
                        "confidence": ioc_data.get("confidence", ""),
                        "first_seen": ioc_data.get("first_seen", ""),
                        "details": ioc_data
                    }
            
            return {
                "matched": False,
                "available": True,
                "source": "ThreatFox",
                "threat_type": "unknown"
            }
            
        except Exception as e:
            self.logger.error(f"ThreatFox check failed: {e}")
            return {"matched": False, "available": False, "error": str(e)}
    
    def _check_spamhaus(self, url: str) -> dict[str, Any]:
        """
        Check IP against Spamhaus DROP lists.
        
        Spamhaus DROP contains high-confidence malicious network ranges.
        Check the resolved IP of the domain against DROP.
        
        IMPORTANT: Requires DNS resolution first. If IP is in DROP, major risk signal.
        """
        try:
            # Get IP address for domain
            domain = urlparse(url).netloc
            
            # Resolve domain to IP
            import socket
            try:
                ip_address = socket.gethostbyname(domain)
            except socket.gaierror:
                return {
                    "matched": False,
                    "available": False,
                    "note": "Could not resolve domain"
                }
            
            # Download DROP list (in production, cache this)
            drop_url = "https://www.spamhaus.org/drop/drop.txt"
            
            req = Request(
                drop_url,
                headers={"User-Agent": "Watchtower/1.0"}
            )
            
            ctx = ssl.create_default_context()
            
            with urlopen(req, timeout=10, context=ctx) as response:
                drop_lines = response.read().decode().splitlines()
                
                # Check if IP falls within any DROP range
                for line in drop_lines:
                    if line.startswith(";") or not line.strip():
                        continue
                    
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        network = parts[0]
                        
                        # Simple CIDR check (production should use ipaddress module)
                        if ip_address.startswith(network.rsplit(".", 1)[0]):
                            return {
                                "matched": True,
                                "available": True,
                                "source": "Spamhaus DROP",
                                "threat_type": "malicious_network",
                                "network": network,
                                "ip": ip_address
                            }
            
            return {
                "matched": False,
                "available": True,
                "source": "Spamhaus DROP",
                "ip": ip_address
            }
            
        except Exception as e:
            self.logger.error(f"Spamhaus check failed: {e}")
            return {"matched": False, "available": False, "error": str(e)}
    
    def check_greynoise(self, ip_address: str) -> dict[str, Any]:
        """
        Check IP reputation using GreyNoise Community API.
        
        Provides classification, noise level, RIOT status, organization info.
        Free tier has rate limits.
        
        Signal: Domain suspicious + IP has malicious history = Higher confidence
        """
        try:
            api_key = self.config.get("greynoise_api_key", "")
            
            if not api_key:
                return {
                    "available": False,
                    "note": "GreyNoise API key not configured"
                }
            
            # GreyNoise Community API endpoint
            api_url = f"https://api.greynoise.io/v3/community/{ip_address}"
            
            req = Request(
                api_url,
                headers={
                    "User-Agent": "Watchtower/1.0",
                    "key": api_key
                }
            )
            
            ctx = ssl.create_default_context()
            
            with urlopen(req, timeout=10, context=ctx) as response:
                data = json.loads(response.read().decode())
                
                return {
                    "available": True,
                    "ip": ip_address,
                    "classification": data.get("classification", "unknown"),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "organization": data.get("organization", ""),
                    "tags": data.get("tags", []),
                    "last_updated": data.get("last_updated", "")
                }
                
        except Exception as e:
            self.logger.error(f"GreyNoise check failed: {e}")
            return {"available": False, "error": str(e)}


def get_threat_intelligence(config: dict[str, Any]) -> ThreatIntelligence:
    """Factory function to create ThreatIntelligence instance."""
    return ThreatIntelligence(config)


# Export main classes
__all__ = ["ThreatIntelligence", "get_threat_intelligence"]
