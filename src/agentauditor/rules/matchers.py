"""Pattern matchers for the rule engine."""

from __future__ import annotations

import fnmatch
import re
from functools import lru_cache

from agentauditor.core.models import PatternMatch


@lru_cache(maxsize=512)
def _compile_regex(pattern: str, case_sensitive: bool) -> re.Pattern:
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(pattern, flags)


class PatternMatcher:
    """Stateless pattern matcher. Compiles and caches regex patterns for performance."""

    def match(self, pattern: PatternMatch, text: str) -> str | None:
        """Test a pattern against text. Returns the matched substring or None."""
        if not text:
            return None

        match pattern.type:
            case "regex":
                compiled = _compile_regex(pattern.value, pattern.case_sensitive)
                m = compiled.search(text)
                return m.group(0) if m else None

            case "glob":
                target = text if pattern.case_sensitive else text.lower()
                pat = pattern.value if pattern.case_sensitive else pattern.value.lower()
                if fnmatch.fnmatch(target, pat):
                    return pattern.value
                return None

            case "keyword":
                target = text if pattern.case_sensitive else text.lower()
                kw = pattern.value if pattern.case_sensitive else pattern.value.lower()
                if kw in target:
                    return pattern.value
                return None

            case "startswith":
                target = text if pattern.case_sensitive else text.lower()
                prefix = pattern.value if pattern.case_sensitive else pattern.value.lower()
                if target.startswith(prefix):
                    return pattern.value
                return None

            case _:
                return None
