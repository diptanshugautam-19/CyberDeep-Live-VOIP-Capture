import logging

logger = logging.getLogger(__name__)

class DPIEngine:
    def __init__(self):
        pass

    def inspect_packet(self, packet: dict, raw_payload: bytes | None = None) -> list[dict]:
        """DPI inspection stub (disabled to prioritize native pipeline parsing)."""
        return []

dpi_engine = DPIEngine()
