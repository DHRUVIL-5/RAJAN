"""
RAJAN Scope Enforcer
Hard blocks any request that goes outside defined scope.
Critical for bug bounty — out-of-scope testing = banned from HackerOne.
Every agent checks this before making ANY request.
"""

import re
import fnmatch
from urllib.parse import urlsplit


class ScopeEnforcer:
    def __init__(self, target, scope=""):
        self.target = target.lower().strip()
        self.scope_raw = scope.strip()
        self.allowed_patterns = self._parse_scope(target, scope)

    def _parse_scope(self, target, scope):
        patterns = []
        # The target itself is authorized by default. Subdomains require
        # explicit scope rather than being implicitly authorized.
        target_host = self._normalize_host(target)
        if target_host:
            patterns.append(target_host)
        # Parse user-defined scope
        if scope:
            for part in scope.replace(",", " ").split():
                part = part.strip().lower()
                if part:
                    normalized = self._normalize_host(part)
                    if normalized:
                        patterns.append(normalized)
        return patterns

    @staticmethod
    def _normalize_host(value):
        value = str(value or "").strip().lower()
        if not value:
            return ""
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname
        if not host:
            return ""
        return host.rstrip(".")

    def is_in_scope(self, url_or_host):
        """Returns True if URL/host is within scope"""
        if not url_or_host:
            return False

        # Extract and normalize the hostname using URL parsing.
        host = self._normalize_host(url_or_host)
        if not host:
            return False

        for pattern in self.allowed_patterns:
            # Exact match
            if host == pattern:
                return True
            # Wildcard match e.g. *.example.com
            if fnmatch.fnmatch(host, pattern):
                return True
            # Subdomain match
            if pattern.startswith("*."):
                base = pattern[2:]
                if host == base or host.endswith(f".{base}"):
                    return True

        return False

    def check(self, url_or_host, logger=None, agent="ScopeEnforcer"):
        """
        Check scope and log warning if out of scope.
        Returns True if in scope, False if blocked.
        """
        in_scope = self.is_in_scope(url_or_host)
        if not in_scope and logger:
            logger.warning(
                f"OUT OF SCOPE — blocked: {url_or_host} "
                f"(scope: {self.scope_raw or self.target})",
                agent
            )
        return in_scope

    def filter_list(self, urls, logger=None):
        """Filter a list of URLs/hosts to only in-scope ones"""
        result = []
        for url in urls:
            if self.is_in_scope(url):
                result.append(url)
            elif logger:
                logger.warning(f"Filtered out-of-scope: {url}", "ScopeEnforcer")
        return result

    def describe(self):
        return f"Target: {self.target} | Scope: {self.scope_raw or 'Full target'}"
