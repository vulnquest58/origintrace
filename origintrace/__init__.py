"""origintrace — evidence-first origin intelligence for authorised testing.

Public surface:

* :class:`ScanContext` carries state through the pipeline.
* :class:`Evidence` records one observation with a weight and a confidence.
* :class:`Candidate` is an IP under investigation.
* :class:`Verdict` is the scored decision about a candidate.

The scoring rules are explained in ``docs/EVIDENCE-MODEL.md``.
"""

from origintrace.models import (
    Candidate,
    Evidence,
    EvidenceKind,
    Finding,
    OriginType,
    ScanContext,
    Verdict,
)

__all__ = [
    "Candidate",
    "Evidence",
    "EvidenceKind",
    "Finding",
    "OriginType",
    "ScanContext",
    "Verdict",
    "__version__",
]

__version__ = "1.0.0"
