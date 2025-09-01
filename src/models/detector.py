"""Simple detector shim used by tests and higher-level code.

This file provides a lightweight `Detector` class with a `detect()` method so
unit tests can import and exercise a deterministic behaviour. The real ML
predictor lives elsewhere (ml_predictor.py) and can be integrated later.
"""

from typing import Iterable, Optional


class Detector:
    """Minimal phishing detector used for tests.

    Behavior: simple rule-based checks for obvious phishing indicators. This
    keeps the test-suite deterministic and fast. The class can be replaced or
    extended to delegate to the ML predictor when available.
    """

    SUSPICIOUS_KEYWORDS = {
        'phishing', 'urgent', 'verify', 'account', 'suspended', 'login',
        'bank', 'click', 'password', 'invoice', 'claim', 'prize'
    }

    def __init__(self, keywords: Optional[Iterable[str]] = None):
        if keywords:
            self.keywords = set(keywords)
        else:
            self.keywords = set(self.SUSPICIOUS_KEYWORDS)

    def detect(self, text: str) -> bool:
        """Return True if the provided text looks like a phishing message.

        The detection is intentionally conservative for tests: if any of the
        suspicious keywords appear (case-insensitive) the method returns True.
        """
        if not text:
            return False

        t = text.lower()
        for kw in self.keywords:
            if kw in t:
                return True
        return False


__all__ = ["Detector"]