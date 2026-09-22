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

Batches: pass several PDFs and/or folders. Every document in one run shares a
salt, so the same account reads as the same token across all of them.

    python sanitize/sanitize_pdf.py statements/ --recursive --skip-existing \
        --names .local/pii-names.txt --strict
    python sanitize/sanitize_pdf.py statements/ --recursive --newer-than 2026-09-15T12:40 \
        --names .local/pii-names.txt --strict

`--skip-existing` skips a PDF whose `.sanitized.md` is already at least as new
as the PDF, which is how "only the new downloads" is expressed without a date.
One unreadable or scanned file is reported as FAILED and the batch continues;
a batch prints a summary table. Exit codes: 0 clean, 1 residual matches under
`--strict`, 2 any input not found or failed.

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
from datetime import datetime
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


def _protect_matches(text: str, kind: str) -> list[re.Match]:
    """Return the protected spans of one kind in their declared precedence order."""
    matches: list[re.Match] = []
    occupied: list[tuple[int, int]] = []
    for protect_kind, pattern in PROTECT:
        if protect_kind != kind:
            continue
        for match in pattern.finditer(text):
            if any(a < match.end() and match.start() < b for a, b in occupied):
                continue
            matches.append(match)
            occupied.append((match.start(), match.end()))
    return matches


def _strict_fragment_of_amount(name_match: re.Match, amount_match: re.Match) -> bool:
    """True only when the listed value is smaller than the amount's numeric core.

    Currency signs, signs and whitespace are wrappers, not evidence that a complete
    listed numeric value is merely an amount fragment. Thus listed ``403.00`` must
    redact ``$403.00`` while listed ``403`` inside ``$1,403.50`` is ambiguous.
    """
    wrapper = re.match(r"[-+]?\$?\s*", amount_match.group(0))
    core_start = amount_match.start() + (wrapper.end() if wrapper else 0)
    core_end = amount_match.end()
    return (core_start <= name_match.start()
            and name_match.end() <= core_end
            and (name_match.start(), name_match.end()) != (core_start, core_end))


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
        # Anchor each alternative to a word boundary. Without this the pass is a
        # plain substring match, and a short given name is a substring of
        # ordinary words: a list carrying "Lance" turned every "Balance" on an
        # RBC statement into "Ba[NAME-1a2b]". Lookarounds rather than \b,
        # because \b is defined relative to whatever sits at the edge of the
        # pattern and a name may legitimately begin or end with punctuation
        # (O'Brien, a trailing period), where \b asserts the opposite of what
        # is wanted. \w excludes U+00A0, so a name wrapped in non-breaking
        # spaces still matches.
        # Accepted cost: a name run together with adjacent letters and no
        # separator at all ("MRLANCEORTEGA") no longer matches. Extraction
        # keeps name fields separate; the demonstrated failure was the other
        # direction, and it corrupted the analysable text on every page.
        return re.compile(rf"(?<!\w)(?:{'|'.join(patterns)})(?!\w)", re.I)

    def scrub(self, text: str) -> str:
        holds: dict[str, str] = {}

        def hold(m: re.Match) -> str:
            key = f"\x00{len(holds)}\x00"
            holds[key] = m.group(0)
            return key

        def run(det: Detector, s_text: str) -> str:
            def sub(m: re.Match) -> str:
                s = m.group(0)
                if det.validate and not det.validate(s):
                    return s
                self.counts[det.name] += 1
                return self.token(det.label, s)
            return det.pattern.sub(sub, s_text)

        # 1. Detectors that must beat the names pass (email).
        for det in self.detectors:
            if det.before_names:
                text = run(det, text)

        # 2. Named individuals - ahead of the address rule, since a name can
        #    sit inside an address span, and ahead of step 3's parking: a
        #    listed entry is the operator saying the value identifies someone,
        #    which overrules protection. A birth date on the list was parked as
        #    a date, never seen by this pass, and restored in plaintext
        #    (2026-09-21, an insurance renewal notice).
        #    One exception keeps an amount analysable: a listed value that is a
        #    strict fragment of the amount's numeric core is preserved. It is
        #    counted as name_in_amount and residuals() reports it, so --strict
        #    requires human review instead of declaring a false clean. Currency
        #    signs, signs and whitespace are wrappers: listed "403.00" redacts
        #    "$403.00", while listed "403" inside "$1,403.50" is ambiguous.
        #    Every other overlap consumes the complete protected span. That
        #    prevents partial names from corrupting an amount and prevents a
        #    listed month or day from exposing the rest of a protected date to
        #    the later long-digit detector (2026-09-22 Codex review).
        npat = self._name_pattern()
        if npat:
            amount_matches = _protect_matches(text, "amount")
            date_matches = _protect_matches(text, "date")
            replacements: list[tuple[int, int, set[int]]] = []
            ambiguous = 0
            for index, match in enumerate(npat.finditer(text)):
                dates = [p for p in date_matches
                         if p.start() < match.end() and match.start() < p.end()]
                amounts = [p for p in amount_matches
                           if p.start() < match.end() and match.start() < p.end()]
                if dates:
                    replacements.append((min([match.start()] + [p.start() for p in dates]),
                                         max([match.end()] + [p.end() for p in dates]), {index}))
                elif amounts and all(_strict_fragment_of_amount(match, p) for p in amounts):
                    ambiguous += 1
                elif amounts:
                    replacements.append((min([match.start()] + [p.start() for p in amounts]),
                                         max([match.end()] + [p.end() for p in amounts]), {index}))
                else:
                    replacements.append((match.start(), match.end(), {index}))

            merged: list[tuple[int, int, set[int]]] = []
            for start, end, indexes in sorted(replacements):
                if merged and start < merged[-1][1]:
                    old_start, old_end, old_indexes = merged[-1]
                    merged[-1] = (old_start, max(old_end, end), old_indexes | indexes)
                else:
                    merged.append((start, end, indexes))
            for start, end, indexes in reversed(merged):
                original = text[start:end]
                text = text[:start] + self.token("NAME", original) + text[end:]
                self.counts["name"] += len(indexes)
            self.counts["name_in_amount"] += ambiguous

        # 3. Park amounts and dates so the pattern detectors cannot reach them.
        for _kind, pat in PROTECT:
            text = pat.sub(hold, text)

        # 4. Remaining structured identifiers, most specific first.
        for det in self.detectors:
            if not det.before_names:
                text = run(det, text)

        # 5. Restore the parked values.
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
        if npat:
            amount_matches = _protect_matches(text, "amount")
            names = list(npat.finditer(text))
            ambiguous = sum(1 for match in names
                            if any(_strict_fragment_of_amount(match, amount)
                                   for amount in amount_matches))
            missed = len(names) - ambiguous
            if missed:
                found["name"] = missed
            if ambiguous:
                found["name_in_amount"] = ambiguous
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


def parse_newer_than(value: str) -> float:
    """An ISO date or datetime in local time, as a POSIX timestamp."""
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an ISO date or datetime: {value!r}") from exc


def collect_pdfs(inputs: list[Path], recursive: bool) -> tuple[list[Path], list[Path]]:
    """Expand files and folders into PDFs, in argument order, without duplicates."""
    found: list[Path] = []
    missing: list[Path] = []
    seen: set[Path] = set()
    for item in inputs:
        if item.is_dir():
            walker = item.rglob("*") if recursive else item.glob("*")
            candidates = sorted(p for p in walker if p.is_file() and p.suffix.lower() == ".pdf")
        elif item.is_file():
            candidates = [item]
        else:
            missing.append(item)
            continue
        for pdf in candidates:
            key = pdf.resolve()
            if key not in seen:
                seen.add(key)
                found.append(pdf)
    return found, missing


def sanitize_one(pdf: Path, *, salt: str, names: list[str], min_digits: int,
                 out_dir: Path, dry_run: bool) -> tuple[dict, dict]:
    """Sanitize one PDF. Returns a summary row and the pseudonym mapping it produced.

    A failure (encrypted, no extractable text, unreadable) is returned as a row with
    status "failed" rather than raised, so one bad file never stops a batch.
    """
    san = Sanitizer(salt=salt, detectors=build_detectors(min_digits), names=names)
    source_meta = describe_source_metadata(pdf)
    try:
        pages = extract_pages(pdf)
    except SystemExit as exc:
        print(f"{pdf.name}: FAILED - {exc}")
        return {"file": pdf, "status": "failed", "error": str(exc)}, {}
    except Exception as exc:  # noqa: BLE001 - a malformed PDF must not stop the batch
        print(f"{pdf.name}: FAILED - {type(exc).__name__}: {exc}")
        return {"file": pdf, "status": "failed", "error": f"{type(exc).__name__}: {exc}"}, {}
    if not any(p.strip() for p in pages):
        msg = ("No extractable text - this is likely a scanned image PDF. "
               "OCR it locally first; do not send the image to a cloud model.")
        print(f"{pdf.name}: FAILED - {msg}")
        return {"file": pdf, "status": "failed", "error": msg}, {}

    out_pages = [san.scrub(p) for p in pages]
    body = "\n\n".join(f"<!-- page {i} -->\n{p.rstrip()}" for i, p in enumerate(out_pages, 1))
    # Broker downloads put the account number in the file name, joined by underscores. An underscore is a
    # word character, so the names pass cannot match inside the raw name: scrub it with each underscore as an
    # en space (whitespace to the regex, and absent from real file names, so it maps back to "_" exactly).
    # The output files keep the source stem; only the text written into them is scrubbed.
    source_name = san.scrub(pdf.stem.replace("_", " ")).replace(" ", "_") + pdf.suffix
    doc = (f"# Sanitized extract: {source_name}\n\n"
           f"Identifiers replaced with stable pseudonyms. Amounts, dates and merchant "
           f"names preserved. Original PDF metadata discarded.\n\n---\n\n{body}\n")

    residual = san.residuals(doc)
    report = {
        "source_file": source_name,
        "source_container": source_meta,
        "redactions_by_type": dict(sorted(san.counts.items(), key=lambda kv: -kv[1])),
        "redactions_total": sum(san.counts.values()),
        "distinct_tokens": len(san.mapping),
        "names_list_supplied": bool(names),
        "min_digits": min_digits,
        "residual_matches": residual,
        "residual_clean": not residual,
    }

    out_md = out_dir / f"{pdf.stem}.sanitized.md"
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_md.write_text(doc, encoding="utf-8")
        (out_dir / f"{pdf.stem}.redaction-report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")

    print(f"{pdf.name}: {len(pages)} pages, {report['redactions_total']} redactions "
          f"({report['distinct_tokens']} distinct)")
    for k, v in report["redactions_by_type"].items():
        print(f"  {k:16} {v}")
    if not names:
        print("  ! no --names list supplied: personal names are NOT being redacted")
    if residual:
        print(f"  ! RESIDUAL MATCHES IN OUTPUT: {residual}")
    if not dry_run:
        print(f"  -> {out_md}")
    print("  Read the output before sharing it. Pattern matching is not a guarantee.")

    row = {"file": pdf, "status": "sanitized", "pages": len(pages),
           "redactions": report["redactions_total"], "residual": residual}
    return row, san.mapping


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", type=Path, metavar="PDF_OR_FOLDER",
                    help="one or more PDFs and/or folders of PDFs")
    ap.add_argument("--recursive", action="store_true",
                    help="also take PDFs from sub-folders of a folder input")
    ap.add_argument("--newer-than", type=parse_newer_than, metavar="ISO",
                    help="only PDFs modified at or after this local date or time, "
                         "e.g. 2026-09-15 or 2026-09-15T12:40")
    ap.add_argument("--skip-existing", action="store_true",
                    help="skip a PDF whose .sanitized.md is already at least as new as the PDF")
    ap.add_argument("--out-dir", type=Path, help="default: alongside each input")
    ap.add_argument("--names", type=Path,
                    help="file of names/terms to redact, one per line; # comments allowed")
    ap.add_argument("--mapping", type=Path,
                    help="write pseudonym->original table for the whole run. CONTAINS PII. Keep it local.")
    ap.add_argument("--salt", help="reuse a salt so tokens stay stable across runs "
                                   "(within one run every document already shares a salt)")
    ap.add_argument("--min-digits", type=int, default=7,
                    help="digit runs this long or longer are treated as identifiers (default 7)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if the residual scan finds anything in any output")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    args = ap.parse_args()

    names: list[str] = []
    if args.names:
        if not args.names.is_file():
            raise SystemExit(f"names file not found: {args.names}")
        names = [ln.strip() for ln in args.names.read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]

    pdfs, missing = collect_pdfs(args.inputs, args.recursive)
    for item in missing:
        print(f"not found: {item}")
    if args.newer_than is not None:
        pdfs = [p for p in pdfs if p.stat().st_mtime >= args.newer_than]

    skipped: list[Path] = []
    if args.skip_existing:
        pending = []
        for pdf in pdfs:
            existing = (args.out_dir or pdf.parent) / f"{pdf.stem}.sanitized.md"
            if existing.is_file() and existing.stat().st_mtime >= pdf.stat().st_mtime:
                skipped.append(pdf)
            else:
                pending.append(pdf)
        pdfs = pending

    if args.out_dir:
        clashes = sorted(stem for stem, n in Counter(p.stem for p in pdfs).items() if n > 1)
        if clashes:
            raise SystemExit(f"--out-dir would overwrite outputs: {clashes} share a file name. "
                             "Run them separately or drop --out-dir.")

    salt = args.salt or secrets.token_hex(8)
    rows: list[dict] = []
    mapping: dict = {}
    for pdf in pdfs:
        row, doc_mapping = sanitize_one(pdf, salt=salt, names=names, min_digits=args.min_digits,
                                        out_dir=args.out_dir or pdf.parent, dry_run=args.dry_run)
        rows.append(row)
        mapping.update(doc_mapping)

    if args.mapping and not args.dry_run and mapping:
        args.mapping.parent.mkdir(parents=True, exist_ok=True)
        args.mapping.write_text(json.dumps({"salt": salt, "mapping": mapping}, indent=2),
                                encoding="utf-8")
        print(f"-> {args.mapping}  (CONTAINS PII - keep local)")

    failed = [r for r in rows if r["status"] == "failed"]
    with_residual = [r for r in rows if r.get("residual")]
    if len(rows) + len(skipped) + len(missing) != 1:
        print(f"\nSummary: {len(rows) - len(failed)} sanitized, {len(skipped)} skipped "
              f"(already sanitized), {len(failed)} failed, {len(missing)} not found, "
              f"{len(with_residual)} with residual matches")
        for r in rows:
            if r["status"] == "failed":
                print(f"  FAILED     {r['file']}")
            else:
                flag = "RESIDUAL" if r["residual"] else "clean"
                print(f"  {flag:9}  {r['pages']:>3} pages {r['redactions']:>4} redactions  {r['file']}")
        for pdf in skipped:
            print(f"  skipped    {pdf}")
    if not rows and not skipped and not missing:
        print("no PDFs matched")

    if missing or failed:
        return 2
    return 1 if (args.strict and with_residual) else 0


if __name__ == "__main__":
    sys.exit(main())
