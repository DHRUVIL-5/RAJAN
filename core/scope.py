"""
RAJAN Scope Enforcer
Hard-blocks requests outside the target and explicitly configured scope.
"""

import fnmatch
import ipaddress
from urllib.parse import urlsplit


class ScopeEnforcer:
    def __init__(self, target, scope=""):
        self.target = self._normalize_host(target)
        self.scope_raw = (scope or "").strip()
        self.allowed_patterns = self._parse_scope(target, scope)

    @staticmethod
    def _normalize_host(value):
        if not value:
            return ""
        raw = str(value).strip()
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname or raw.split("/", 1)[0]
        host = host.strip().rstrip(".").lower()
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return host

    @classmethod
    def _normalize_pattern(cls, value):
        pattern = str(value).strip()
        if not pattern:
            return ""
        if "://" in pattern:
            parsed = urlsplit(pattern)
            prefix = "*." if parsed.hostname and pattern.lstrip().startswith("*.") else ""
            pattern = prefix + (parsed.hostname or "")
        else:
            pattern = pattern.split("/", 1)[0]
        if pattern.startswith("*:"):
            pattern = "*" + pattern[2:]
        if pattern.startswith("[" ) and "]" in pattern:
            pattern = pattern[1:pattern.index("]")]
        elif pattern.count(":") == 1:
            pattern = pattern.rsplit(":", 1)[0]
        return cls._normalize_host(pattern)

    def _parse_scope(self, target, scope):
        target_host = self._normalize_host(target)
        patterns = []
        if target_host:
            patterns.append(target_host)
            try:
                ipaddress.ip_address(target_host)
            except ValueError:
                patterns.append(f"*.{target_host}")
        for part in (scope or "").replace(",", " ").split():
            normalized = self._normalize_pattern(part)
            if normalized and normalized not in patterns:
                patterns.append(normalized)
        return patterns

    def is_in_scope(self, url_or_host):
        """Return True only when the hostname matches an allowed pattern."""
        host = self._normalize_host(url_or_host)
        if not host:
            return False
        for pattern in self.allowed_patterns:
            if host == pattern:
                return True
            if pattern.startswith("*."):
                base = pattern[2:]
                if host != base and host.endswith(f".{base}"):
                    return True
            elif any(ch in pattern for ch in "?["):
                if fnmatch.fnmatchcase(host, pattern):
                    return True
        return False

    def check(self, url_or_host, logger=None, agent="ScopeEnforcer"):
        in_scope = self.is_in_scope(url_or_host)
        if not in_scope and logger:
            logger.warning(
                f"OUT OF SCOPE — blocked: {url_or_host} "
                f"(scope: {self.scope_raw or self.target})", agent
            )
        return in_scope

    def filter_list(self, urls, logger=None):
        result = []
        for url in urls:
            if self.is_in_scope(url):
                result.append(url)
            elif logger:
                logger.warning(f"Filtered out-of-scope: {url}", "ScopeEnforcer")
        return result

    def describe(self):
        return f"Target: {self.target} | Scope: {self.scope_raw or 'Full target'}"
