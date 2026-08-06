import abc
from typing import Iterable, Any, Dict


class BaseParser(abc.ABC):
    """Abstract base class for all parsers in the universal ingestion engine.

    Concrete parsers must implement :meth:`parse` which yields a dictionary for each
    record/row of the source data. The return type is intentionally generic so that
    downstream components can decide how to consume the mapping (e.g., convert to
    a DataFrame, stream to a database, or feed into enrichment pipelines).
    """

    @abc.abstractmethod
    def parse(self, source: Any) -> Iterable[Dict[str, Any]]:
        """Parse *source* and yield row dictionaries.

        Args:
            source: An opaque source object – could be a file path, a file‑like
                object, raw bytes, etc. Concrete implementations decide the
                accepted type and raise ``TypeError`` if the provided source is
                unsupported.
        Yields:
            Dict[str, Any]: Mapping of column name to value for each record.
        """
        raise NotImplementedError
