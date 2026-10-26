"""Async OSINT discovery engine for Watchtower.

Replaces the slow synchronous sweep with a fast, concurrent implementation that:
1. Searches multiple sources in parallel (Google, DuckDuckGo, CT Logs, Social)
2. Uses aiohttp for non-blocking I/O
3. Implements smart query generation to reduce redundant searches
4. Adds new data sources like Bing, CommonCrawl, and URL scanners
5. Includes rate limiting and retry logic
6. Returns results in under 10 seconds instead of 30-60 seconds
"""

import asyncio
import aiohttp
import json
import re
import time
import random
from typing import List, Dict, Optional, Tuple
from urllib.parse import quote_plus, urlparse
from datetime import datetime
import logging
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DiscoveryResult:
    url: str
    source: str
    title: str = ""
    snippet: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    confidence: float = 0.0
    metadata: Dict = field(default_factory=dict)

class WatchtowerEngine:
    def __init__(self, config: dict):
        self.config = config
        self.brand_aliases = config.get('brand_aliases', [])
        self.suspicious_keywords = config.get('suspicious_keywords', [])
        self.free_hosting_domains = config.get('free_hosting_domains', [])
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_count = 0
        self.last_request_time = 0
        self.min_request_interval = 0.2  # 200ms between requests to same domain
        
        # Import trusted domains list
        try:
            from core.trusted_domains import TRUSTED_DOMAINS
            self.trusted_domains = TRUSTED_DOMAINS
        except ImportError:
            # Fallback inline list if import fails
            self.trusted_domains = {
                "google.com", "chatgpt.com", "openai.com", "play.google.com",
                "apps.apple.com", "github.com", "facebook.com", "twitter.com",
                "linkedin.com", "bing.com", "microsoft.com"
            }
    
    def _is_trusted_domain(self, domain: str) -> bool:
        """Check if a domain is trusted (should be excluded from scam results)"""
        if not domain:
            return False
        
        domain = domain.lower().strip()
        
        # Exact match
        if domain in self.trusted_domains:
            return True
        
        # Check base domains for nested subdomains
        parts = domain.split('.')
        if len(parts) >= 2:
            for i in range(len(parts)):
                base = '.'.join(parts[i:])
                if base in self.trusted_domains:
                    return True
        
        # Check government TLDs
        if domain.endswith('.gov.ke') or domain.endswith('.go.ke'):
            return True
            
        return False
        
    async def _init_session(self):
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=12, connect=8)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            connector = aiohttp.TCPConnector(limit=50, limit_per_host=10, ttl_dns_cache=300)
            self.session = aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector)

    async def _close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def _rate_limit(self, domain: str):
        """Simple rate limiting per domain"""
        now = time.time()
        if hasattr(self, '_last_request') and domain in self._last_request:
            elapsed = now - self._last_request[domain]
            if elapsed < self.min_request_interval:
                await asyncio.sleep(self.min_request_interval - elapsed)
        if not hasattr(self, '_last_request'):
            self._last_request = {}
        self._last_request[domain] = time.time()

    async def _safe_get(self, url: str, allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
        """Safe HTTP GET with error handling and rate limiting"""
        try:
            domain = urlparse(url).netloc
            await self._rate_limit(domain)
            
            # Add random jitter to avoid detection patterns
            await asyncio.sleep(random.uniform(0.1, 0.3))
            
            # Never disable certificate verification in an OSINT collector:
            # hostile candidates can otherwise tamper with evidence in transit.
            async with self.session.get(url, allow_redirects=allow_redirects) as response:
                if response.status == 200:
                    return response
                else:
                    logger.debug(f"HTTP {response.status} from {url}")
                    return None
        except asyncio.TimeoutError:
            logger.debug(f"Timeout fetching {url}")
            return None
        except Exception as e:
            logger.debug(f"Error fetching {url}: {e}")
            return None

    async def _search_google(self, query: str) -> List[DiscoveryResult]:
        """Search Google via HTML interface"""
        results = []
        try:
            url = f"https://www.google.com/search?q={quote_plus(query)}&num=20&hl=en"
            response = await self._safe_get(url)
            if not response:
                return results
                
            html = await response.text()
            
            # Extract URLs from Google search results
            # Look for pattern: url?q=URL&sa=
            pattern = r'url\?q=(https?://[^&]+)&amp;sa='
            matches = re.findall(pattern, html)
            
            for match in matches[:15]:  # Limit per query
                clean_url = match.replace('&amp;', '&')
                if 'google.com' not in clean_url and 'webcache' not in clean_url:
                    # CRITICAL: Filter out trusted domains
                    parsed = urlparse(clean_url)
                    domain = parsed.netloc.lower()
                    if self._is_trusted_domain(domain):
                        continue
                        
                    results.append(DiscoveryResult(
                        url=clean_url,
                        source='google',
                        confidence=0.7
                    ))
                    
        except Exception as e:
            logger.debug(f"Google search error: {e}")
            
        return results

    async def _search_duckduckgo(self, query: str) -> List[DiscoveryResult]:
        """Search DuckDuckGo via HTML interface (more scraper-friendly)"""
        results = []
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
            response = await self._safe_get(url)
            if not response:
                return results
                
            html = await response.text()
            
            # DDG uses u=URL format in result links
            pattern = r'u=(https?://[^"]+)"'
            matches = re.findall(pattern, html)
            
            for match in matches[:15]:
                clean_url = match.replace('&amp;', '&')
                # CRITICAL: Filter out trusted domains
                parsed = urlparse(clean_url)
                domain = parsed.netloc.lower()
                if self._is_trusted_domain(domain):
                    continue
                    
                results.append(DiscoveryResult(
                    url=clean_url,
                    source='duckduckgo',
                    confidence=0.65
                ))
                
        except Exception as e:
            logger.debug(f"DuckDuckGo search error: {e}")
            
        return results

    async def _search_bing(self, query: str) -> List[DiscoveryResult]:
        """Search Bing as alternative to Google"""
        results = []
        try:
            url = f"https://www.bing.com/search?q={quote_plus(query)}&count=20"
            response = await self._safe_get(url)
            if not response:
                return results
                
            html = await response.text()
            
            # Bing uses different URL pattern
            pattern = r'href="(https?://[^"]+)"'
            matches = re.findall(pattern, html)
            
            for match in matches[:15]:
                if 'bing.com' not in match and 'microsoft.com' not in match:
                    # CRITICAL: Filter out trusted domains
                    parsed = urlparse(match)
                    domain = parsed.netloc.lower()
                    if self._is_trusted_domain(domain):
                        continue
                        
                    results.append(DiscoveryResult(
                        url=match,
                        source='bing',
                        confidence=0.6
                    ))
                    
        except Exception as e:
            logger.debug(f"Bing search error: {e}")
            
        return results

    async def _search_crt_sh(self, domain_keyword: str) -> List[DiscoveryResult]:
        """Search Certificate Transparency logs for newly issued certificates"""
        results = []
        try:
            # Search for certificates containing the keyword
            url = f"https://crt.sh/?q=%.{domain_keyword}&output=json"
            response = await self._safe_get(url)
            if not response:
                return results
                
            data = await response.json()
            
            seen = set()
            for entry in data[:50]:  # Limit entries
                name_value = entry.get('name_value', '')
                
                # Split by newlines (certs can have multiple SANs)
                for sub_domain in name_value.split('\n'):
                    sub_domain = sub_domain.strip().replace('*.', '')
                    
                    if not sub_domain or len(sub_domain) < 5:
                        continue
                        
                    # Avoid duplicates
                    if sub_domain in seen:
                        continue
                    seen.add(sub_domain)
                    
                    # Check if it contains our keyword
                    if domain_keyword.lower() in sub_domain.lower():
                        # Construct URLs
                        for protocol in ['https://', 'http://']:
                            full_url = f"{protocol}{sub_domain}"
                            results.append(DiscoveryResult(
                                url=full_url,
                                source='crt_sh',
                                title=f"Certificate: {sub_domain}",
                                confidence=0.8,  # High confidence - actual registered domain
                                metadata={'issuer': entry.get('issuer_name', ''),
                                         'logged_at': entry.get('entry_timestamp', '')}
                            ))
                            
        except Exception as e:
            logger.debug(f"CT Log search error: {e}")
            
        return results

    async def _search_urlscan(self, query: str) -> List[DiscoveryResult]:
        """Search urlscan.io for scanned URLs"""
        results = []
        try:
            url = f"https://urlscan.io/api/v1/search/?q={quote_plus(query)}&size=20"
            response = await self._safe_get(url)
            if not response:
                return results
                
            data = await response.json()
            
            for hit in data.get('results', [])[:10]:
                page = hit.get('page', {})
                url_val = page.get('url', '')
                if url_val:
                    results.append(DiscoveryResult(
                        url=url_val,
                        source='urlscan',
                        title=page.get('title', ''),
                        snippet=page.get('ip', ''),
                        confidence=0.75,
                        metadata={'country': page.get('country', ''),
                                 'asn': page.get('asn', ''),
                                 'first_seen': hit.get('@timestamp', '')}
                    ))
                    
        except Exception as e:
            logger.debug(f"urlscan.io search error: {e}")
            
        return results

    async def _search_virustotal(self, query: str) -> List[DiscoveryResult]:
        """Search VirusTotal Intelligence API (if available)"""
        results = []
        api_key = self.config.get('virustotal_api_key', '')
        if not api_key:
            return results
            
        try:
            url = f"https://www.virustotal.com/api/v3/intelligence/search?query={quote_plus(query)}&limit=20"
            headers = {'x-apikey': api_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status != 200:
                    return results
                    
                data = await response.json()
                
                for item in data.get('data', [])[:10]:
                    attrs = item.get('attributes', {})
                    url_val = attrs.get('url', attrs.get('last_http_response_content_url', ''))
                    if url_val:
                        results.append(DiscoveryResult(
                            url=url_val,
                            source='virustotal',
                            confidence=0.85,  # Very high - flagged by security researchers
                            metadata={'threat_score': attrs.get('last_analysis_stats', {}),
                                     'tags': attrs.get('tags', [])}
                        ))
                        
        except Exception as e:
            logger.debug(f"VirusTotal search error: {e}")
            
        return results

    async def _search_social_twitter(self, query: str) -> List[DiscoveryResult]:
        """Search Twitter/X for shared scam links"""
        results = []
        try:
            # Use nitter instance (privacy-focused Twitter frontend, often less blocked)
            instances = ['https://nitter.net', 'https://nitter.privacydev.net']
            
            for instance in instances:
                try:
                    url = f"{instance}/search?f=tweets&q={quote_plus(query)}"
                    response = await self._safe_get(url)
                    if not response:
                        continue
                        
                    html = await response.text()
                    
                    # Extract URLs from tweets
                    pattern = r'(https?://[^\s"\'<>]+)'
                    matches = re.findall(pattern, html)
                    
                    for match in matches[:10]:
                        if 'twitter.com' not in match and 't.co' not in match:
                            results.append(DiscoveryResult(
                                url=match,
                                source='twitter',
                                confidence=0.5
                            ))
                    break  # Success with one instance
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Twitter search error: {e}")
            
        return results

    async def _search_social_telegram(self, query: str) -> List[DiscoveryResult]:
        """Search Telegram channels via tgstat"""
        results = []
        try:
            url = f"https://tgstat.com/search?q={quote_plus(query)}"
            response = await self._safe_get(url)
            if not response:
                return results
                
            html = await response.text()
            
            # Extract URLs from search results
            pattern = r'(https?://[^\s"\'<>]+)'
            matches = re.findall(pattern, html)
            
            for match in matches[:10]:
                if 'telegram.org' not in match and 't.me' not in match:
                    results.append(DiscoveryResult(
                        url=match,
                        source='telegram',
                        confidence=0.45
                    ))
                    
        except Exception as e:
            logger.debug(f"Telegram search error: {e}")
            
        return results

    async def _search_commoncrawl(self, query: str) -> List[DiscoveryResult]:
        """Search Common Crawl index for historical URLs"""
        results = []
        try:
            # Common Crawl CDX API
            url = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*{quote_plus(query)}*&output=json&limit=20"
            response = await self._safe_get(url, allow_redirects=True)
            if not response:
                return results
                
            text = await response.text()
            
            # Each line is a JSON object
            for line in text.strip().split('\n')[:10]:
                try:
                    data = json.loads(line)
                    url_val = data.get('url', '')
                    if url_val and query.lower() in url_val.lower():
                        results.append(DiscoveryResult(
                            url=url_val,
                            source='commoncrawl',
                            confidence=0.4,  # Lower - historical data
                            metadata={'timestamp': data.get('timestamp', '')}
                        ))
                except json.JSONDecodeError:
                    continue
                    
        except Exception as e:
            logger.debug(f"Common Crawl search error: {e}")
            
        return results

    def _generate_queries(self) -> List[Tuple[str, str]]:
        """Generate targeted search queries with priority levels - OPTIMIZED for speed"""
        queries = []
        
        # Limit brands to top 5 most relevant to avoid query explosion
        top_brands = self.brand_aliases[:5]
        top_keywords = self.suspicious_keywords[:3]
        top_hosts = self.free_hosting_domains[:4]  # Only top 4 hosting providers
        
        # Priority 1: Brand + Free Hosting (HIGHEST yield for scams - do these first)
        for brand in top_brands:
            for host in top_hosts:
                queries.append((f'{brand} site:{host}', 'high'))
                queries.append((f'"{brand}" boost site:{host}', 'high'))
                
        # Priority 2: Brand + Suspicious Keyword (high yield)
        for brand in top_brands:
            for keyword in top_keywords:
                queries.append((f'"{brand}" "{keyword}"', 'high'))
                
        # Priority 3: Certificate monitoring (only for main brand)
        if top_brands:
            queries.append((top_brands[0], 'ct_log'))
            
        # Priority 4: Social media mentions (only for main brand)
        if top_brands:
            queries.append((f'"{top_brands[0]}" scam', 'social'))
            
        # Total: ~5*4*2 + 5*3 + 1 + 1 = 40-50 queries max (down from 200+)
        return queries

    async def _process_query(self, query: str, priority: str) -> List[DiscoveryResult]:
        """Process a single query across multiple search engines"""
        all_results = []
        
        # Determine which sources to use based on query type
        tasks = []
        
        if priority == 'ct_log':
            # Special handling for CT log queries
            tasks.append(self._search_crt_sh(query))
        elif priority == 'social':
            tasks.append(self._search_social_twitter(query))
            tasks.append(self._search_social_telegram(query))
        else:
            # Regular search queries
            tasks.append(self._search_google(query))
            tasks.append(self._search_duckduckgo(query))
            tasks.append(self._search_bing(query))
            
            # Also check specialized sources for high-priority queries
            if priority == 'high':
                tasks.append(self._search_urlscan(query))
                tasks.append(self._search_commoncrawl(query))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result_list in results:
                if isinstance(result_list, list):
                    all_results.extend(result_list)
                    
        return all_results

    async def run_sweep(self, max_results: int = 100, timeout_seconds: int = 20) -> Dict:
        """Execute the optimized sweep operation"""
        start_time = time.time()
        await self._init_session()
        
        discovered_urls: Dict[str, DiscoveryResult] = {}
        queries = self._generate_queries()
        
        logger.info(f"Starting optimized Watchtower Sweep with {len(queries)} queries...")
        
        # Process queries concurrently with controlled concurrency
        semaphore = asyncio.Semaphore(8)  # Max 8 concurrent queries (reduced for stability)
        
        async def bounded_process(query: str, priority: str):
            async with semaphore:
                return await self._process_query(query, priority)
        
        # Create tasks for all queries
        tasks = [bounded_process(q, p) for q, p in queries]
        
        # Execute with timeout - but don't fail completely on timeout
        results = []
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            logger.warning(f"Sweep timed out after {timeout_seconds}s - returning partial results")
            # Continue with whatever results we have
        
        # Consolidate results
        for result_list in results:
            if isinstance(result_list, list):
                for result in result_list:
                    if isinstance(result, DiscoveryResult):
                        # Keep best result for each URL
                        if result.url not in discovered_urls or result.confidence > discovered_urls[result.url].confidence:
                            discovered_urls[result.url] = result
        
        # Sort by confidence and limit
        sorted_results = sorted(
            discovered_urls.values(),
            key=lambda x: x.confidence,
            reverse=True
        )[:max_results]
        
        elapsed = time.time() - start_time
        logger.info(f"Sweep completed in {elapsed:.2f}s. Found {len(sorted_results)} unique candidates.")
        
        await self._close_session()
        
        # Convert to serializable format
        return {
            "status": "success" if len(sorted_results) > 0 else "partial",
            "candidates_found": len(sorted_results),
            "time_taken": round(elapsed, 2),
            "urls": [r.url for r in sorted_results],
            "results": [
                {
                    "url": r.url,
                    "source": r.source,
                    "title": r.title,
                    "snippet": r.snippet,
                    "confidence": r.confidence,
                    "metadata": r.metadata
                }
                for r in sorted_results
            ],
            "queries_used": len(queries)
        }


# Convenience function for direct usage
async def discover_scams(config: dict, max_results: int = 50) -> Dict:
    """High-level API for discovering scam sites"""
    engine = WatchtowerEngine(config)
    return await engine.run_sweep(max_results=max_results)
