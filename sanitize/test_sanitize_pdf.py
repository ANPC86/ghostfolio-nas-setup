"""Adversarial test for sanitize/sanitize_pdf.py.

Builds a PDF stuffed with synthetic identifiers, sanitizes it, and asserts that
none of them survive in plaintext. Every case here is a defect the test caught
during development, not a hypothetical:

  - a card number failing its Luhn check passed straight through, because Luhn
    was gating redaction rather than annotating it;
  - a personal name inside an email local part split the address in two,
    because the names pass ran ahead of the email rule;
  - an IBAN lost only its digits to the card rule, leaving country and bank
    code exposed - and the residual scan could not see it, because what
    remained no longer matched the IBAN pattern;
  - a listed given name ate part of an ordinary word, because the names pass
    was a plain substring match: "Lance" on the list turned every "Balance" on
    an RBC statement into "Ba[NAME-1a2b]", on every page.

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

sys.path.insert(0, str(SCRIPT.parent))
import sanitize_pdf  # noqa: E402  - imported for the pattern-level test below

NAMES = ["Jordan Alvarez-Whitcombe", "Alvarez-Whitcombe", "Jordan", "Lance"]

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
    "Lance",                    # as a name in its own right - see MUST_SURVIVE
]

# Analysis payload: must be preserved or the output is useless. "Balance" and
# "Freelancer" are here because "Lance" is on the names list and is a substring
# of both - at the end of one word and inside the other.
MUST_SURVIVE = [
    "CORNER GROCER #14",
    "-142.87", "4,318.22", "-1,200.00", "+3,450.00", "-12,345.67",
    "2026-03-04", "2026-03-22",
    "Balance", "Freelancer",
]

BODY = """NORTHBANK FINANCIAL - Chequing Statement
Account Holder: Jordan Alvarez-Whitcombe
Joint holder: Lance Alvarez-Whitcombe
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
2026-03-20  Freelancer invoice paid              -500.00   6,042.78
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


def test_names_pass_respects_word_boundaries():
    """A listed name must not eat part of an ordinary word.

    Scrubbed directly rather than through a PDF because the non-breaking space
    matters here, and whether one survives a render-then-extract round trip is
    the renderer's business, not this rule's.
    """
    san = sanitize_pdf.Sanitizer(
        salt="fixed", detectors=sanitize_pdf.build_detectors(7),
        names=["Lance", "Jordan Alvarez-Whitcombe"])
    out = san.scrub("Balance and Freelancer stay. Lance goes. "
                    "So does Jordan Alvarez-Whitcombe.")

    assert "Balance" in out and "Freelancer" in out
    assert "Lance goes" not in out                    # standalone, still redacted
    assert "Jordan" not in out                        # \xa0 inside a name still matches
    assert san.counts["name"] == 2, out


def test_a_listed_identifier_shaped_like_a_date_is_redacted():
    """A names-list entry wins over date protection.

    Found on an insurance renewal notice (2026-09-21): a birth date put on the
    names list survived, because dates are parked before the names pass runs,
    so the pass never saw it - and the residual scan, which runs on the output,
    then reported it. Listing a value is the operator saying it identifies
    someone; protection exists to keep pattern detectors off amounts and dates,
    not to overrule an explicit entry. Other dates and amounts must still stay.
    """
    san = sanitize_pdf.Sanitizer(
        salt="fixed", detectors=sanitize_pdf.build_detectors(7),
        names=["October 19, 1990", "19-Oct-1990"])
    out = san.scrub("Date of birth: October 19, 1990\nBorn 19-Oct-1990\n"
                    "Renewal date: November 1, 2025  Premium $60.21  2026-03-04")

    assert "1990" not in out, out
    assert "November 1, 2025" in out and "$60.21" in out and "2026-03-04" in out
    assert san.counts["name"] == 2, out
    assert not san.residuals(out), san.residuals(out)


def test_a_listed_number_never_eats_part_of_a_larger_amount():
    """A listed short number is redacted where it stands alone, never inside an amount.

    Regression from the fix above (2026-09-22): once the names pass ran ahead of
    protection, a listed "403" turned "$403.00" into "$[NAME-...].00" and
    "1,403.50" into "1,[NAME-...].50", silently corrupting the analysis payload.
    An entry that is only a fragment of a larger amount is left alone; one that
    is the whole amount, or any part of a date, is still redacted, because a
    leaked birth-date fragment costs more than an over-redacted date.
    """
    san = sanitize_pdf.Sanitizer(
        salt="fixed", detectors=sanitize_pdf.build_detectors(7),
        names=["403", "October 19"])
    out = san.scrub("Suite 403. Paid $403.00 and 1,403.50 and 403.25 today. "
                    "Born October 19, 1990. Renewal November 1, 2025.")

    assert "Suite 403" not in out, f"standalone listed number survived: {out}"
    assert "$403.00" in out, f"amount fragment was redacted: {out}"
    assert "1,403.50" in out, f"thousands amount fragment was redacted: {out}"
    assert "403.25" in out, f"decimal amount fragment was redacted: {out}"
    assert "October 19" not in out, f"listed fragment of a date survived: {out}"
    assert "November 1, 2025" in out, f"unlisted date was redacted: {out}"
    assert not san.residuals(out), f"residual scan must honour the same exception: {san.residuals(out)}"


# ---- batches: folders, new-download filters, one bad file, shared tokens -------------------------
# Synthetic content only. Each document carries the same invented account number so the shared-salt
# property is visible, plus a phone number the residual scan would catch if it survived.

BATCH_TEXT = "Account Number: 12345-004-8871902\nPhone (403) 555-0182\n2026-03-04  GROCER  -14.20\n"


def _make_pdf(path: Path, text: str | None) -> Path:
    doc = fitz.open()
    page = doc.new_page()
    if text:
        page.insert_text((40, 60), text, fontsize=9, fontname="cour")
    doc.save(path)
    doc.close()
    return path


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_batch_folder_shares_tokens_across_documents(tmp_path):
    folder = tmp_path / "statements"
    folder.mkdir()
    a = _make_pdf(folder / "a.pdf", BATCH_TEXT)
    b = _make_pdf(folder / "b.pdf", BATCH_TEXT)
    proc = _run(str(folder), "--strict")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Summary: 2 sanitized, 0 skipped" in proc.stdout
    import re
    tokens = [set(re.findall(r"\[ACCT-[0-9a-f]{4}\]", (folder / f"{p.stem}.sanitized.md").read_text(encoding="utf-8")))
              for p in (a, b)]
    assert tokens[0] and tokens[0] == tokens[1], tokens
    for p in (a, b):
        assert "8871902" not in (folder / f"{p.stem}.sanitized.md").read_text(encoding="utf-8")


def test_batch_newer_than_and_skip_existing_select_only_new_downloads(tmp_path):
    import os
    old = _make_pdf(tmp_path / "old.pdf", BATCH_TEXT)
    new = _make_pdf(tmp_path / "new.pdf", BATCH_TEXT)
    os.utime(old, (1_700_000_000, 1_700_000_000))          # 2023-11-14, well before the cutoff
    proc = _run(str(tmp_path), "--newer-than", "2024-01-01", "--strict")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (tmp_path / "new.sanitized.md").is_file()
    assert not (tmp_path / "old.sanitized.md").exists()

    proc = _run(str(tmp_path), "--skip-existing", "--strict")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1 sanitized, 1 skipped" in proc.stdout, proc.stdout
    assert (tmp_path / "old.sanitized.md").is_file()
    assert f"skipped    {new}" in proc.stdout


def test_batch_reports_a_scanned_pdf_as_failed_and_continues(tmp_path):
    _make_pdf(tmp_path / "blank.pdf", None)                 # no text layer: stands in for a scan
    _make_pdf(tmp_path / "good.pdf", BATCH_TEXT)
    proc = _run(str(tmp_path), "--strict")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "blank.pdf: FAILED" in proc.stdout
    assert (tmp_path / "good.sanitized.md").is_file()
    assert not (tmp_path / "blank.sanitized.md").exists()


def test_batch_refuses_out_dir_name_clash(tmp_path):
    for sub in ("x", "y"):
        (tmp_path / sub).mkdir()
        _make_pdf(tmp_path / sub / "statement.pdf", BATCH_TEXT)
    proc = _run(str(tmp_path), "--recursive", "--out-dir", str(tmp_path / "out"))
    assert proc.returncode != 0
    assert "would overwrite" in (proc.stdout + proc.stderr)
    assert not (tmp_path / "out").exists()


def test_missing_input_exits_2(tmp_path):
    proc = _run(str(tmp_path / "nope.pdf"))
    assert proc.returncode == 2
    assert "not found" in proc.stdout


def test_listed_identifier_in_the_filename_does_not_reach_the_output(tmp_path):
    """Broker downloads carry the account number in the file name, joined by underscores.

    The header line and the report's source_file copied the name verbatim, and an underscore is a word character,
    so the names pass's word-boundary lookarounds could never match inside it.
    """
    pdf = _make_pdf(tmp_path / "ACCT77QX9USD_client-9ZZtest_2024-08_v_0.pdf", BATCH_TEXT)
    names = tmp_path / "names.txt"
    names.write_text("ACCT77QX9USD\n", encoding="utf-8")
    proc = _run(str(pdf), "--names", str(names), "--strict")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = (tmp_path / f"{pdf.stem}.sanitized.md").read_text(encoding="utf-8")
    report = (tmp_path / f"{pdf.stem}.redaction-report.json").read_text(encoding="utf-8")
    assert "ACCT77QX9USD" not in out, out.splitlines()[0]
    assert "ACCT77QX9USD" not in report
    assert "2024-08" in out.splitlines()[0]          # the rest of the name still identifies the period


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
