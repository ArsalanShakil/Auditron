"""Policy version migration registry.

Manages schema migrations between policy versions. Each migration is a
function that transforms a raw policy dict from one version to another.
"""

from __future__ import annotations

import warnings
from typing import Any, Callable


class PolicyVersion:
    """Semantic version for policies."""

    def __init__(self, version_str: str) -> None:
        parts = version_str.strip().split(".")
        self.major = int(parts[0])
        self.minor = int(parts[1]) if len(parts) > 1 else 0
        self.patch = int(parts[2]) if len(parts) > 2 else 0

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def __repr__(self) -> str:
        return f"PolicyVersion('{self}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PolicyVersion):
            return NotImplemented
        return self._tuple == other._tuple

    def __lt__(self, other: PolicyVersion) -> bool:
        return self._tuple < other._tuple

    def __le__(self, other: PolicyVersion) -> bool:
        return self._tuple <= other._tuple

    def __gt__(self, other: PolicyVersion) -> bool:
        return self._tuple > other._tuple

    def __ge__(self, other: PolicyVersion) -> bool:
        return self._tuple >= other._tuple

    def __hash__(self) -> int:
        return hash(self._tuple)

    @property
    def _tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


# Current policy schema version
CURRENT_POLICY_VERSION = PolicyVersion("1.0.0")


MigrationFn = Callable[[dict[str, Any]], dict[str, Any]]


class MigrationRegistry:
    """Registry of policy schema migrations."""

    def __init__(self) -> None:
        self._migrations: dict[tuple[str, str], MigrationFn] = {}

    def register(
        self, from_version: str, to_version: str
    ) -> Callable[[MigrationFn], MigrationFn]:
        """Decorator to register a migration function."""
        def decorator(fn: MigrationFn) -> MigrationFn:
            self._migrations[(from_version, to_version)] = fn
            return fn
        return decorator

    def migrate(
        self, raw: dict[str, Any], from_version: PolicyVersion
    ) -> dict[str, Any]:
        """Migrate a policy dict from from_version to CURRENT_POLICY_VERSION.

        Finds and applies migrations sequentially.
        """
        current = from_version
        target = CURRENT_POLICY_VERSION

        if current == target:
            return raw

        if current > target:
            raise ValueError(
                f"Policy version {current} is newer than supported version {target}. "
                f"Please upgrade AgentAuditor."
            )

        # Try direct migration first
        key = (str(current), str(target))
        if key in self._migrations:
            warnings.warn(
                f"Migrating policy from version {current} to {target}",
                DeprecationWarning,
                stacklevel=3,
            )
            raw = self._migrations[key](raw)
            raw["version"] = str(target)
            return raw

        # No migration path found — normalize version and return
        warnings.warn(
            f"Policy version {current} is outdated. "
            f"Consider updating to {target}.",
            DeprecationWarning,
            stacklevel=3,
        )
        raw["version"] = str(target)
        return raw


# Global migration registry
_registry = MigrationRegistry()


@_registry.register("1.0", "1.0.0")
def _migrate_1_0_to_1_0_0(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize version string from '1.0' to '1.0.0'. No schema changes."""
    return raw


def get_registry() -> MigrationRegistry:
    """Get the global migration registry."""
    return _registry
