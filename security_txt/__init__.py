"""security-txt: check and generate RFC 9116 security.txt files."""

from .core import Analysis, Issue, analyze, parse, parse_expires
from .generate import build
from .net import DomainResult, check_domain, fetch

__version__ = "1.0.0"
__all__ = ["Analysis", "Issue", "analyze", "parse", "parse_expires", "build",
           "DomainResult", "check_domain", "fetch", "__version__"]
