"""Strip personal identifiers from a PDF and emit text safe to share with a cloud model.

Why text out, never PDF out
---------------------------
A "redacted" PDF with black rectangles drawn over the sensitive parts still
contains the original text in its content stream; copy-paste or any extractor
recovers it. Anything that redacts in place is a false sense of safety. This
script extracts text, rewrites it, and discards the original container -
along with PDF metadata, embedded files, annotations and XMP, none of which
survive the trip.

What survives, and why
----------------------
Financial analysis needs dates, amounts, merchant names and transaction
descriptions. Those are preserved by default. Account numbers, card numbers,
SINs, phone numbers, emails, postal codes and named individuals are replaced
with stable pseudonyms, so `[ACCT-7f3a]` still reads as the same account
everywhere it appears and the document stays analysable.

Trust model
-----------
Detection is pattern-based and therefore imperfect. Two guards follow from
that. First, the run reports exactly what it replaced, by type and count, so
the redaction is reviewable rather than assumed. Second, `--strict` re-scans
the OUTPUT and exits non-zero if anything matching a high-risk pattern
survived. Read the output before sharing it. A script cannot certify that a
document is safe; it can only remove what it recognises.

Usage
-----
    python sanitize/sanitize_pdf.py statement.pdf
    python sanitize/sanitize_pdf.py statement.pdf --names .local/pii-names.txt --strict
    python sanitize/sanitize_pdf.py statement.pdf --dry-run

Outputs `<input>.sanitized.md` and `<input>.redaction-report.json` next to the
input unless `--out-dir` says otherwise. `--mapping FILE` additionally writes
the pseudonym-to-original table; that file contains the very data you are
trying to protect, so keep it in an ignored directory and never share it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Protected spans: matched FIRST and held out of detection, so that the
# generic long-digit rule cannot swallow the numbers the analysis depends on.
# A balance like 1234567.89 is a digit run; an account number is too. Order
# is what separates them.
# --------------------------------------------------------------------------

PROTECT = [
    ("amount", re.compile(r"(?<![\w-])[-+]?\$?\s?\d{1,3}(?:,\d{3})+(?:\.\d{2})?(?![\w])")),
    ("amount", re.compile(r"(?<![\w-])[-+]?\$\s?\d+(?:\.\d{1,2})?(?![\w])")),
    ("amount", re.compile(r"(?<![\w-])[-+]?\d+\.\d{2}(?![\w])")),
    ("date", re.compile(r"\b\d{4}-\d{2}-\d{2}\b")),
    ("date", re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b")),
    ("date", re.compile(
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2}(?:,?\s+\d{4})?\b",
        re.I)),
    ("date", re.compile(
        r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?(?:,?\s+\d{4})?\b",
        re.I)),
]


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass
class Detector:
    name: str
    label: str
    pattern: re.Pattern
    validate: object = None       # optional callable(match_text) -> bool
    high_risk: bool = True        # counted by --strict residual scan
    before_names: bool = False    # run ahead of the names pass


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def build_detectors(min_digits: int) -> list[Detector]:
    return [
        # Email runs before the names pass: a personal name inside a local part
        # would otherwise be replaced first, splitting the address in two.
        Detector("email", "EMAIL",
                 re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
                 before_names=True),
        # IBAN ahead of the card rule. An IBAN ends in a long digit run, and a
        # card match would eat it, leaving the country and bank code exposed as
        # plaintext - a partial leak the residual scan cannot see, because what
        # remains no longer matches the IBAN pattern.
        Detector("iban", "IBAN",
                 re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9][ ]?){10,30}\b")),
        # Most specific numeric form next so it wins the label: a Canadian
        # transit-institution-account triple is also card-shaped by length.
        Detector("bank_account", "ACCT",
                 re.compile(r"(?<![\d])\d{5}[ -]\d{3}[ -]\d{7,12}(?![\d])")),
        # Card-SHAPED, not card-verified. Luhn is deliberately NOT a gate here:
        # a transposed digit or a partially-masked PAN still must not survive,
        # and over-redacting a long reference number costs nothing. Luhn only
        # annotates confidence in the report.
        Detector("credit_card", "CARD",
                 re.compile(r"(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])"),
                 lambda s: 13 <= len(_digits(s)) <= 19),
        # Canadian SIN carries a Luhn checksum, which keeps false positives low
        # on a 9-digit run. Here the check is affordable: a real SIN passes it.
        Detector("sin", "SIN",
                 re.compile(r"(?<![\d])\d{3}[ -]?\d{3}[ -]?\d{3}(?![\d])"),
                 lambda s: len(_digits(s)) == 9 and _luhn(_digits(s))),
        Detector("phone", "PHONE",
                 re.compile(r"(?<![\d])(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\d])")),
        Detector("postal_code", "POSTAL",
                 re.compile(r"\b[A-Z]\d[A-Z][ -]?\d[A-Z]\d\b")),
        # Catch-all for anything account-shaped the specific rules missed.
        # Runs last; protected amounts and dates are already out of scope.
        Detector("long_digits", "NUM",
                 re.compile(rf"(?<![\d])\d{{{min_digits},}}(?![\d])")),
        Detector("street_address", "ADDR",
                 re.compile(
                     r"\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][\w'-]*\s+){0,3}"
                     r"(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Boulevard|Blvd|Crescent|Cres|"
                     r"Way|Court|Ct|Place|Pl|Lane|Ln|Trail|Terrace|Terr|Gate|Green|Grove|Bay|Close|Link|Row)"
                     r"\.?(?:\s+(?:NW|NE|SW|SE|N|S|E|W))?\b"),
                 high_risk=False),
    ]


@dataclass
class Sanitizer:
    salt: str
    detectors: list[Detector]
    names: list[str] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    mapping: dict = field(default_factory=dict)

    def token(self, label: str, value: str) -> str:
        key = re.sub(r"\s+", "", value).upper()
        digest = hashlib.sha256((self.salt + "|" + label + "|" + key).encode()).hexdigest()[:4]
        tok = f"[{label}-{digest}]"
        self.mapping.setdefault(tok, value.strip())
        return tok

    def _name_pattern(self) -> re.Pattern | None:
        if not self.names:
            return None
        parts = sorted((n.strip() for n in self.names if n.strip()), key=len, reverse=True)
        if not parts:
            return None
        # A literal " " only ever matched an ASCII space. PDF text extraction
        # commonly uses U+00A0 (non-breaking space) inside a name field
        # instead - "HOMER J SIMPSON" came out as "HOMER\xa0J\xa0SIMPSON" and
        # silently failed to match. Escape each word on its own (never a
        # string containing a space - re.escape emits "\ " for one, and
        # patching that after the fact doubles the backslash) and join with
        # \s+, which covers \xa0 and any run of whitespace from wrapping.
        patterns = ["\\s+".join(re.escape(w) for w in p.split()) for p in parts]
        return re.compile("|".join(patterns), re.I)

    def scrub(self, text: str) -> str:
        holds: dict[str, str] = {}

        def hold(m: re.Match) -> str:
            key = f"\x00{len(holds)}\x00"
            holds[key] = m.group(0)
            return key

        # 1. Park amounts and dates so detection cannot reach them.
        for _kind, pat in PROTECT:
            text = pat.sub(hold, text)

        def run(det: Detector, s_text: str) -> str:
            def sub(m: re.Match) -> str:
                s = m.group(0)
                if det.validate and not det.validate(s):
                    return s
                self.counts[det.name] += 1
                return self.token(det.label, s)
            return det.pattern.sub(sub, s_text)

        # 2. Detectors that must beat the names pass (email).
        for det in self.detectors:
            if det.before_names:
                text = run(det, text)

        # 3. Named individuals - ahead of the address rule, since a name can
        #    sit inside an address span.
        npat = self._name_pattern()
        if npat:
            def sub_name(m: re.Match) -> str:
                self.counts["name"] += 1
                return self.token("NAME", m.group(0))
            text = npat.sub(sub_name, text)

        # 4. Remaining structured identifiers, most specific first.
        for det in self.detectors:
            if not det.before_names:
                text = run(det, text)

        # 4. Restore the parked values.
        for key, original in holds.items():
            text = text.replace(key, original)
        return text

    def residuals(self, text: str) -> dict[str, int]:
        """Re-scan OUTPUT. Anything found here escaped the first pass."""
        found: dict[str, int] = {}
        for det in self.detectors:
            if not det.high_risk:
                continue
            hits = [m.group(0) for m in det.pattern.finditer(text)
                    if not (det.validate and not det.validate(m.group(0)))]
            hits = [h for h in hits if not re.fullmatch(r"\[[A-Z]+-[0-9a-f]{4}\]", h.strip())]
            if hits:
                found[det.name] = len(hits)
        npat = self._name_pattern()
        if npat and (n := len(npat.findall(text))):
            found["name"] = n
        return found


def extract_pages(pdf: Path) -> list[str]:
    try:
        import fitz  # PyMuPDF
        with fitz.open(pdf) as doc:
            if doc.is_encrypted and not doc.authenticate(""):
                raise SystemExit(f"{pdf.name} is password-protected; decrypt it first.")
            return [p.get_text("text") for p in doc]
    except ImportError:
        pass
    try:
        from pypdf import PdfReader
    except ImportError:
        raise SystemExit("Needs PyMuPDF or pypdf: python -m pip install pymupdf")
    reader = PdfReader(str(pdf))
    if reader.is_encrypted:
        reader.decrypt("")
    return [(p.extract_text() or "") for p in reader.pages]


def describe_source_metadata(pdf: Path) -> dict:
    """Report what the container held. None of it reaches the output."""
    try:
        import fitz
        with fitz.open(pdf) as doc:
            md = {k: v for k, v in (doc.metadata or {}).items() if v}
            return {
                "metadata_fields_discarded": sorted(md.keys()),
                "pages": doc.page_count,
                "embedded_files_discarded": doc.embfile_count(),
                "has_xmp_discarded": bool(doc.xref_xml_metadata()),
            }
    except Exception:
        return {}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pdf", type=Path)
    ap.add_argument("--out-dir", type=Path, help="default: alongside the input")
    ap.add_argument("--names", type=Path,
                    help="file of names/terms to redact, one per line; # comments allowed")
    ap.add_argument("--mapping", type=Path,
                    help="write pseudonym->original table. CONTAINS PII. Keep it local.")
    ap.add_argument("--salt", help="reuse a salt so tokens stay stable across documents")
    ap.add_argument("--min-digits", type=int, default=7,
                    help="digit runs this long or longer are treated as identifiers (default 7)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if the residual scan finds anything")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    args = ap.parse_args()

    if not args.pdf.is_file():
        raise SystemExit(f"not found: {args.pdf}")

    names: list[str] = []
    if args.names:
        if not args.names.is_file():
            raise SystemExit(f"names file not found: {args.names}")
        names = [ln.strip() for ln in args.names.read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]

    salt = args.salt or secrets.token_hex(8)
    san = Sanitizer(salt=salt, detectors=build_detectors(args.min_digits), names=names)

    source_meta = describe_source_metadata(args.pdf)
    pages = extract_pages(args.pdf)
    if not any(p.strip() for p in pages):
        raise SystemExit(
            "No extractable text - this is likely a scanned image PDF. "
            "OCR it locally first; do not send the image to a cloud model.")

    out_pages = [san.scrub(p) for p in pages]
    body = "\n\n".join(f"<!-- page {i} -->\n{p.rstrip()}" for i, p in enumerate(out_pages, 1))
    doc = (f"# Sanitized extract: {args.pdf.name}\n\n"
           f"Identifiers replaced with stable pseudonyms. Amounts, dates and merchant "
           f"names preserved. Original PDF metadata discarded.\n\n---\n\n{body}\n")

    residual = san.residuals(doc)
    report = {
        "source_file": args.pdf.name,
        "source_container": source_meta,
        "redactions_by_type": dict(sorted(san.counts.items(), key=lambda kv: -kv[1])),
        "redactions_total": sum(san.counts.values()),
        "distinct_tokens": len(san.mapping),
        "names_list_supplied": bool(names),
        "min_digits": args.min_digits,
        "residual_matches": residual,
        "residual_clean": not residual,
    }

    out_dir = args.out_dir or args.pdf.parent
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{args.pdf.stem}.sanitized.md").write_text(doc, encoding="utf-8")
        (out_dir / f"{args.pdf.stem}.redaction-report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
        if args.mapping:
            args.mapping.parent.mkdir(parents=True, exist_ok=True)
            args.mapping.write_text(json.dumps(
                {"salt": salt, "mapping": san.mapping}, indent=2), encoding="utf-8")

    print(f"{args.pdf.name}: {len(pages)} pages, {report['redactions_total']} redactions "
          f"({report['distinct_tokens']} distinct)")
    for k, v in report["redactions_by_type"].items():
        print(f"  {k:16} {v}")
    if not names:
        print("  ! no --names list supplied: personal names are NOT being redacted")
    if residual:
        print(f"  ! RESIDUAL MATCHES IN OUTPUT: {residual}")
    if not args.dry_run:
        print(f"  -> {out_dir / (args.pdf.stem + '.sanitized.md')}")
        if args.mapping:
            print(f"  -> {args.mapping}  (CONTAINS PII - keep local)")
    print("  Read the output before sharing it. Pattern matching is not a guarantee.")

    return 1 if (args.strict and residual) else 0


if __name__ == "__main__":
    sys.exit(main())
