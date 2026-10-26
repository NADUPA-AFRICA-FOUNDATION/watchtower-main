"""
Enrichment module for Watchtower.

Provides enrichment functions for URLs:
- DNS records
- RDAP/WHOIS information  
- TLS certificate details
- IP reputation
- ASN/hosting information
- HTTP/page analysis
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen, Request
import hashlib

logger = logging.getLogger(__name__)


class EnrichmentEngine:
    """
    Collects enrichment data for URLs and domains.
    
    Coordinates multiple enrichment sources to build comprehensive
    infrastructure profiles.
    """
    
    def __init__(self, config: dict[str, Any]):
        """
        Initialize enrichment engine.
        
        Args:
            config: Configuration with API keys and settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def enrich_url(self, url: str) -> dict[str, Any]:
        """
        Perform full enrichment on a URL.
        
        Returns:
            Dictionary with all enrichment data
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else ""
        
        result = {
            "url": url,
            "domain": domain,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }
        
        # DNS enrichment
        result["dns"] = self.get_dns_records(domain)
        
        # RDAP/WHOIS enrichment
        result["registration"] = self.get_registration_info(domain)
        
        # TLS certificate enrichment
        result["tls"] = self.get_tls_certificate(domain)
        
        # IP and ASN enrichment
        ip_result = self.get_ip_info(domain)
        result["ip"] = ip_result.get("ip", "")
        result["asn"] = ip_result.get("asn", "")
        result["hosting"] = ip_result.get("hosting", "")
        
        # HTTP/page enrichment (if URL is accessible)
        result["http"] = self.get_http_info(url)
        
        return result
    
    def get_dns_records(self, domain: str) -> dict[str, Any]:
        """
        Get DNS records for domain.
        
        Returns A, AAAA, MX, NS, TXT records.
        """
        result = {
            "domain": domain,
            "records": {}
        }
        
        try:
            # A record
            try:
                a_records = socket.gethostbyname_ex(domain)[2]
                result["records"]["A"] = a_records
            except socket.gaierror:
                result["records"]["A"] = []
            
            # MX records (would need dnspython library for full implementation)
            # For now, placeholder
            result["records"]["MX"] = []
            
            # NS records
            result["records"]["NS"] = []
            
            # TXT records
            result["records"]["TXT"] = []
            
        except Exception as e:
            self.logger.error(f"DNS lookup failed for {domain}: {e}")
            result["error"] = str(e)
        
        return result
    
    def get_registration_info(self, domain: str) -> dict[str, Any]:
        """
        Get domain registration information via RDAP.
        
        Returns registration date, registrar, nameservers, etc.
        """
        result = {
            "domain": domain,
            "registered_date": None,
            "registrar": "",
            "nameservers": [],
            "status": [],
        }
        
        try:
            # Try RDAP (Registration Data Access Protocol)
            rdap_url = f"https://rdap.verisign.com/com/v1/domain/{domain}"
            
            req = Request(
                rdap_url,
                headers={"User-Agent": "Watchtower/1.0"}
            )
            
            ctx = ssl.create_default_context()
            
            try:
                with urlopen(req, timeout=10, context=ctx) as response:
                    data = json.loads(response.read().decode())
                    
                    # Extract registration date
                    events = data.get("events", [])
                    for event in events:
                        if event.get("eventAction") == "registration":
                            result["registered_date"] = event.get("eventDate", "")
                    
                    # Extract registrar
                    entities = data.get("entities", [])
                    for entity in entities:
                        roles = entity.get("roles", [])
                        if "registrar" in roles:
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        result["registrar"] = item[3]
                    
                    # Extract nameservers
                    nameservers = data.get("nameservers", [])
                    result["nameservers"] = [ns["ldhName"] for ns in nameservers]
                    
            except Exception:
                # Fallback: try whois lookup (basic implementation)
                result = self._whois_fallback(domain, result)
                
        except Exception as e:
            self.logger.error(f"RDAP lookup failed for {domain}: {e}")
            result["error"] = str(e)
        
        return result
    
    def _whois_fallback(self, domain: str, result: dict[str, Any]) -> dict[str, Any]:
        """Fallback WHOIS lookup when RDAP fails."""
        # Basic implementation - would use python-whois library in production
        return result
    
    def get_tls_certificate(self, domain: str) -> dict[str, Any]:
        """
        Get TLS certificate information.
        
        Returns issuer, validity dates, subject, SANs.
        """
        result = {
            "domain": domain,
            "has_tls": False,
            "issuer": "",
            "subject": "",
            "valid_from": "",
            "valid_to": "",
            "sans": [],
            "age_days": None,
        }
        
        try:
            # Connect and get certificate
            ctx = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        result["has_tls"] = True
                        
                        # Extract issuer
                        issuer_items = dict(item[0] for item in cert.get("issuer", []))
                        result["issuer"] = issuer_items.get("organization", issuer_items.get("commonName", ""))
                        
                        # Extract subject
                        subject_items = dict(item[0] for item in cert.get("subject", []))
                        result["subject"] = subject_items.get("organization", subject_items.get("commonName", ""))
                        
                        # Extract validity dates
                        not_before = cert.get("notBefore", "")
                        not_after = cert.get("notAfter", "")
                        
                        result["valid_from"] = not_before
                        result["valid_to"] = not_after
                        
                        # Calculate certificate age
                        try:
                            from datetime import datetime
                            valid_from_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                            age = (datetime.now(timezone.utc) - valid_from_dt.replace(tzinfo=timezone.utc)).days
                            result["age_days"] = age
                        except Exception:
                            pass
                        
                        # Extract Subject Alternative Names
                        san_ext = cert.get("subjectAltName", [])
                        result["sans"] = [name[1] for name in san_ext if name[0] == "DNS"]
                        
        except Exception as e:
            self.logger.debug(f"TLS certificate lookup failed for {domain}: {e}")
            # Don't log as error - many domains won't have TLS
        
        return result
    
    def get_ip_info(self, domain: str) -> dict[str, Any]:
        """
        Get IP address and ASN information.
        
        Returns IP, ASN, hosting provider, country.
        """
        result = {
            "domain": domain,
            "ip": "",
            "asn": "",
            "asn_name": "",
            "hosting": "",
            "country": "",
        }
        
        try:
            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain)
            result["ip"] = ip_address
            
            # Get ASN info (would use IP geolocation API in production)
            # Placeholder for now
            result["asn"] = ""
            result["asn_name"] = ""
            result["hosting"] = ""
            result["country"] = ""
            
        except socket.gaierror:
            result["error"] = "Could not resolve domain"
        except Exception as e:
            self.logger.error(f"IP lookup failed for {domain}: {e}")
            result["error"] = str(e)
        
        return result
    
    def get_http_info(self, url: str) -> dict[str, Any]:
        """
        Get HTTP/page information.
        
        Returns status code, redirects, title, forms detected.
        """
        result = {
            "url": url,
            "status_code": 0,
            "redirect_chain": [],
            "title": "",
            "has_login_form": False,
            "has_password_field": False,
            "has_payment_form": False,
            "content_hash": "",
        }
        
        try:
            # Would use requests library in production for full HTTP analysis
            # For now, basic implementation
            
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; Watchtower/1.0)"
                }
            )
            
            ctx = ssl.create_default_context()
            
            with urlopen(req, timeout=20, context=ctx) as response:
                result["status_code"] = response.status
                
                # Get redirect chain
                result["redirect_chain"] = [url]  # Would track redirects in production
                
                # Read content
                html = response.read().decode("utf-8", errors="ignore")[:50000]
                
                # Extract title
                title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I)
                if title_match:
                    result["title"] = title_match.group(1).strip()
                
                # Detect forms
                if re.search(r'<form[^>]*login', html, re.I):
                    result["has_login_form"] = True
                
                if re.search(r'<input[^>]*type=["\']password', html, re.I):
                    result["has_password_field"] = True
                
                if re.search(r'(payment|pay|mpesa|mobile.?money)', html, re.I):
                    result["has_payment_form"] = True
                
                # Compute content hash
                result["content_hash"] = hashlib.sha256(html.encode()).hexdigest()[:16]
                
        except Exception as e:
            self.logger.debug(f"HTTP fetch failed for {url}: {e}")
            result["error"] = str(e)
        
        return result


def get_enrichment_engine(config: dict[str, Any]) -> EnrichmentEngine:
    """Factory function to create EnrichmentEngine instance."""
    return EnrichmentEngine(config)


# Export main classes
__all__ = ["EnrichmentEngine", "get_enrichment_engine"]
