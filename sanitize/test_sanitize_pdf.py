"""Adversarial test for scripts/sanitize_pdf.py.

Builds a PDF stuffed with synthetic identifiers, sanitizes it, and asserts that
none of them survive in plaintext. Every case here is a defect the test caught
during development, not a hypothetical:

  - a card number failing its Luhn check passed straight through, because Luhn
    was gating redaction rather than annotating it;
  - a personal name inside an email local part split the address in two,
    because the names pass ran ahead of the email rule;
  - an IBAN lost only its digits to the card rule, leaving country and bank
    code exposed - and the residual scan could not see it, because what
    remained no longer matched the IBAN pattern.

All identifiers below are invented. Do not put a real statement in this file.

    python -m pytest sanitize/test_sanitize_pdf.py -q
    python sanitize/test_sanitize_pdf.py          # runs standalone too
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

fitz = pytest.importorskip("fitz", reason="PyMuPDF required to build the fixture")

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "sanitize_pdf.py"

NAMES = ["Jordan Alvarez-Whitcombe", "Alvarez-Whitcombe", "Jordan"]

# Strings that must NOT appear anywhere in the sanitized output.
MUST_NOT_SURVIVE = [
    "4539 5788 1234 5682",      # card, Luhn-valid
    "4539578812345682",
    "4539 5788 1234 5678",      # card, Luhn-INVALID - must still go
    "5500005555555559",         # card, no separators
    "046 454 286",              # SIN
    "12345-004-8871902",        # bank account
    "jordan.a.whitcombe@examplemail.ca",
    "(403) 555-0182",
    "403-555-0199",
    "T2N 1P4",                  # postal code
    "900218374465",             # long reference number
    "GB29NWBK60161331926819",   # IBAN, full
    "GB29NWBK",                 # IBAN, partial - the subtle leak
    "4417 Kensington Crescent",
    "Jordan",
    "Alvarez-Whitcombe",
]

# Analysis payload: must be preserved or the output is useless.
MUST_SURVIVE = [
    "CORNER GROCER #14",
    "-142.87", "4,318.22", "-1,200.00", "+3,450.00", "-12,345.67",
    "2026-03-04", "2026-03-22",
]

BODY = """NORTHBANK FINANCIAL - Chequing Statement
Account Holder: Jordan Alvarez-Whitcombe
Address: 4417 Kensington Crescent NW, Calgary AB  T2N 1P4
Account Number: 12345-004-8871902
Card (valid luhn):   4539 5788 1234 5682
Card (typo'd luhn):  4539 5788 1234 5678
Card (no spaces):    5500005555555559
SIN: 046 454 286
Contact: jordan.a.whitcombe@examplemail.ca   (403) 555-0182
Alt phone 403-555-0199    Client Reference 900218374465
IBAN GB29NWBK60161331926819

Date        Description                          Amount    Balance
2026-03-04  CORNER GROCER #14                    -142.87   4,318.22
2026-03-09  Transfer to 12345-004-8871902      -1,200.00   3,099.23
2026-03-18  Payroll deposit - Alvarez-Whitcombe +3,450.00  6,542.78
2026-03-22  Large item                        -12,345.67  -5,802.89
"""


@pytest.fixture(scope="module")
def sanitized(tmp_path_factory) -> tuple[str, dict]:
    d = tmp_path_factory.mktemp("sanitize")
    pdf = d / "fixture.pdf"

    doc = fitz.open()
    doc.new_page().insert_text((40, 60), BODY, fontsize=9, fontname="cour")
    doc.set_metadata({"author": "Jordan Alvarez-Whitcombe",
                      "title": "Statement", "subject": "Acct 8871902"})
    doc.save(pdf)
    doc.close()

    names_file = d / "names.txt"
    names_file.write_text("\n".join(NAMES), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(pdf), "--names", str(names_file), "--strict"],
        capture_output=True, text=True)
    assert proc.returncode == 0, f"strict run failed:\n{proc.stdout}\n{proc.stderr}"

    out = (d / "fixture.sanitized.md").read_text(encoding="utf-8")
    report = json.loads((d / "fixture.redaction-report.json").read_text(encoding="utf-8"))
    return out, report


@pytest.mark.parametrize("secret", MUST_NOT_SURVIVE)
def test_identifier_does_not_survive(sanitized, secret):
    out, _ = sanitized
    assert secret not in out, f"LEAKED: {secret!r}"


@pytest.mark.parametrize("keep", MUST_SURVIVE)
def test_analysis_payload_survives(sanitized, keep):
    out, _ = sanitized
    assert keep in out, f"destroyed analysable content: {keep!r}"


def test_residual_scan_reports_clean(sanitized):
    _, report = sanitized
    assert report["residual_clean"], report["residual_matches"]


def test_same_account_gets_the_same_token(sanitized):
    """The account appears twice; analysis depends on both reading alike."""
    out, _ = sanitized
    import re
    toks = re.findall(r"\[ACCT-[0-9a-f]{4}\]", out)
    assert len(toks) >= 2 and len(set(toks)) == 1, toks


def test_source_metadata_is_reported_and_absent(sanitized):
    out, report = sanitized
    assert "author" in report["source_container"]["metadata_fields_discarded"]
    assert "Jordan" not in out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
