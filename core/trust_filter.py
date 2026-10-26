"""
Trust & Allowlist Module
Filters out legitimate high-trust domains to prevent false positives.
"""

import os
import json
from typing import Set

# Path to store the allowlist data
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
TRANCO_FILE = os.path.join(DATA_DIR, "tranco_top_10k.json")
OFFICIAL_FILE = os.path.join(DATA_DIR, "official_allowlist.json")

class TrustFilter:
    def __init__(self):
        self.high_trust_domains: Set[str] = set()
        self.official_domains: Set[str] = set()
        self._load_data()

    def _load_data(self):
        """Load Tranco top domains and official brand domains."""
        # 1. Load Tranco Top 10k (High Trust Global Sites)
        if os.path.exists(TRANCO_FILE):
            try:
                with open(TRANCO_FILE, 'r') as f:
                    data = json.load(f)
                    # Expecting {"domains": ["google.com", "facebook.com", ...]}
                    self.high_trust_domains = set(d.lower() for d in data.get("domains", []))
            except Exception:
                pass
        
        # Hardcoded fallback for critical top domains if file missing
        if not self.high_trust_domains:
            self.high_trust_domains = {
                "google.com", "youtube.com", "facebook.com", "twitter.com",
                "instagram.com", "linkedin.com", "reddit.com", "wikipedia.org",
                "amazon.com", "microsoft.com", "apple.com", "openai.com",
                "chatgpt.com", "cloudflare.com", "github.com", "stackoverflow.com",
                "vercel.app", "netlify.app", "firebaseapp.com", "blogspot.com",
                "medium.com", "wordpress.com", "play.google.com", "apps.apple.com"
            }

        # 2. Load Official Brand Allowlist
        if os.path.exists(OFFICIAL_FILE):
            try:
                with open(OFFICIAL_FILE, 'r') as f:
                    data = json.load(f)
                    # Expecting {"safaricom": ["safaricom.co.ke", ...], ...}
                    for brand, domains in data.items():
                        for domain in domains:
                            self.official_domains.add(domain.lower())
            except Exception:
                pass
        
        # Hardcoded fallback for key African brands
        if not self.official_domains:
            self.official_domains = {
                "safaricom.co.ke", "mpesa.co.ke", "kcb.co.ke", "equitygroupha.com",
                "co-opbank.co.ke", "ncba.co.ke", "absa.africa", "stanbicbank.co.ke",
                "imbbank.com", "airtel.africa", "tala.co", "branch.co.ke",
                "citizen.go.ke", "kra.go.ke", "nhif.or.ke"
            }

    def is_high_trust(self, domain: str) -> bool:
        """Check if domain is in Tranco Top 10k or major tech platforms."""
        domain = domain.lower()
        # Check exact match
        if domain in self.high_trust_domains:
            return True
        # Check base domain (e.g., play.google.com -> google.com)
        parts = domain.split('.')
        if len(parts) > 2:
            base = '.'.join(parts[-2:])
            if base in self.high_trust_domains:
                return True
        return False

    def is_official_brand_domain(self, domain: str, brand: str = None) -> bool:
        """Check if domain is an official verified domain for a brand."""
        domain = domain.lower()
        if domain in self.official_domains:
            return True
        
        # If brand provided, check specific brand list
        if brand:
            brand = brand.lower()
            # Simple heuristic: if domain contains brand and is high trust, likely safe
            # But strict check requires loaded data
            pass
            
        return False

    def should_ignore(self, domain: str, brand: str = None) -> bool:
        """
        Determine if a URL should be ignored during OSINT hunting.
        Returns True if the site is too trustworthy to be a scam.
        """
        if self.is_high_trust(domain):
            return True
        
        if self.is_official_brand_domain(domain, brand):
            return True
            
        return False

# Singleton instance
trust_filter = TrustFilter()
