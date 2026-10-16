from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SourceResult:
    source_id: str
    proxies: list[dict[str, Any]] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class Source(ABC):
    source_id: str

    @abstractmethod
    def fetch(self) -> SourceResult:
        raise NotImplementedError
