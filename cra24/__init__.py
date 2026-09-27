"""cra24: CRA Article 14 clock management for actively exploited vulnerabilities."""

__version__ = "0.1.0"


class Cra24Error(Exception):
    """A usage or input problem (bad file, unknown incident). The CLI exits 2."""


class TransitionError(Exception):
    """An illegal status change (for example reporting before notifying). The CLI exits 1."""
