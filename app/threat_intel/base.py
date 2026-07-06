from abc import ABC, abstractmethod


class ThreatFeed(ABC):
    name = "base"

    @abstractmethod
    def lookup(self, ip: str) -> dict:
        raise NotImplementedError
