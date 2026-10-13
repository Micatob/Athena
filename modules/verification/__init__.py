"""Second-opinion verification for scanner findings.

The exploitation runner's handlers match success *signatures*; when nothing
matches, a finding used to die as ``inconclusive`` with no further effort.
These modules spend a bounded number of extra requests trying to *prove*
time-based injection (SQLi / SSTI / LDAPi) before giving up:

* :mod:`timing` — differential timing: benign probes vs sleep-payload
  probes, median + MAD statistics, WAF-aware abort.
* :mod:`oob` — out-of-band callbacks via pluggable collectors
  (interactsh, webhook.site, operator-owned domain, local listener).

Both are evidence-only and fail closed: anything unproven stays
``inconclusive``.  Nothing here writes, deletes, or modifies target state.
"""

from modules.verification.oob import (
    OOBConfig,
    OOBResult,
    attempt_oob,
    select_collectors,
)
from modules.verification.timing import (
    TimingConfig,
    TimingResult,
    verify_differential,
)

__all__ = [
    "OOBConfig",
    "OOBResult",
    "TimingConfig",
    "TimingResult",
    "attempt_oob",
    "select_collectors",
    "verify_differential",
]
