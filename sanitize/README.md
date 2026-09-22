# Sanitize a statement before an assistant reads it

**Read this before you paste, upload, or point an AI assistant at any financial document.**

A brokerage statement, a trade confirmation, a tax slip or a bank statement carries more than the numbers you want analysed. It carries your full legal name, your account numbers, your address, your phone number, sometimes your national identifier. Sending that to a cloud model means it leaves your network, is processed on someone else's hardware, and may be retained under terms you did not read. The numbers are what the analysis needs; the identifiers are not.

`sanitize_pdf.py` extracts the text from a PDF, replaces the identifiers with stable pseudonyms, discards the PDF container entirely, and writes a Markdown file that is safe to share. Dates, amounts, ticker symbols, merchant names and transaction descriptions survive, so the output is still analysable — an assistant can turn a sanitized confirmation into a Ghostfolio activity without ever seeing who you are.

## Why not just black out the PDF

A "redacted" PDF with black rectangles drawn over the sensitive parts still contains the original text in its content stream. Copy-paste recovers it; any text extractor recovers it; an LLM given the file recovers it. So do PDF metadata (author name), XMP, embedded files and annotations. Anything that redacts *in place* is a false sense of safety. This script never writes a PDF. Text goes out, nothing else.

## What it replaces, and what it keeps

| Replaced with a pseudonym | Kept verbatim |
|---|---|
| Email addresses, `[EMAIL-3f1a]` | Dates in every common format |
| IBANs, `[IBAN-…]` | Amounts (`1,234.56`, `$12.00`, `-42.87`) |
| Bank and brokerage account numbers, `[ACCT-…]` | Ticker symbols, security names, quantities, unit prices |
| Card numbers, whether or not they pass a Luhn check, `[CARD-…]` | Merchant and payee names |
| National identifiers (Canadian SIN with checksum), `[SIN-…]` | Transaction descriptions |
| Phone numbers, `[PHONE-…]` | Column headings, page structure |
| Postal codes, `[POSTAL-…]` | |
| Any digit run of 7 or more, `[NUM-…]` | |
| Street addresses, `[ADDR-…]` | |
| **Every term in your names file**, `[NAME-…]` | |

Pseudonyms are stable within a run: the same account number becomes the same `[ACCT-7f3a]` on every page, so a transfer between two of your accounts still reads as a transfer between two distinct accounts.

## Install and run

```bash
python -m pip install pymupdf          # or: pip install pypdf (slower, weaker extraction)
python sanitize/sanitize_pdf.py confirmation.pdf --names .local/pii-names.txt --strict
```

Outputs, next to the input unless `--out-dir` says otherwise:

- `confirmation.sanitized.md` — what you share.
- `confirmation.redaction-report.json` — what was replaced, by type and count, and whether the residual scan of the output came back clean.

Run `--dry-run` first on a new document type to see the counts without writing anything.

### Batches

Pass several PDFs and/or folders. Every document in one run shares a salt, so the same account reads as the same token across all of them.

```bash
python sanitize/sanitize_pdf.py confirmations/ --recursive --skip-existing --names .local/pii-names.txt --strict
python sanitize/sanitize_pdf.py confirmations/ --recursive --newer-than 2026-09-15T12:40 --names .local/pii-names.txt --strict
```

- `--skip-existing` skips a PDF whose `.sanitized.md` is already at least as new as the PDF, which is how "only the new downloads" is expressed without a date.
- One unreadable or scanned file is reported as FAILED and the batch continues; a batch prints a summary table.
- Exit codes: `0` clean, `1` residual matches under `--strict`, `2` any input not found or failed.

## The names file — do this, it is the part patterns cannot do

Patterns catch structured identifiers. They cannot know that *Homer Simpson* is you, that *Springfield Savings & Loan* is your bank, or that *Evergreen Terrace* is your street. You tell the script that in a plain text file, one term per line:

```text
# .local/pii-names.txt  — THIS FILE IS PII. Keep it in a gitignored folder. Never share it.
# One term per line. Lines starting with # are ignored. Matching is case-insensitive
# and tolerant of line-wrapping and non-breaking spaces inside a name.

# People — full name, surname alone, and any variant a statement might print
Homer Simpson
Simpson, Homer
SIMPSON HOMER J
Simpson
Marge Simpson

# Employer or clients that would identify you
Springfield Nuclear Power Plant

# Street and building names (the house number is caught by the address rule; the street name is not)
Evergreen Terrace
742 Evergreen Terrace

# Anything else specific to you that a stranger could search for
Springfield Isotopes Season Ticket
```

Guidance that came from real misses:

- **Put in every form the institution prints.** `SIMPSON HOMER J`, `Homer J. Simpson` and `Simpson, Homer` are three different strings. Statements are inconsistent; list them all.
- **Include the surname on its own.** A line like `Payment from SIMPSON` is otherwise missed.
- **Include employers, landlords, tenants and business names**, not only people. A client's name on an invoice narrows you down as surely as your own.
- **List any other value that identifies you, even if it looks like a date or an amount**: a birth date in each printed form (`19-Oct-1990`, `October 19, 1990`), a member or reference number the patterns miss because it is short or oddly spaced, a unit number. A listed entry is redacted even where the script would otherwise protect a date or amount; unlisted dates and amounts stay.
- **Do not include merchants, issuers or tickers you want to keep** (a fund issuer, an exchange, a grocer). They are the analysis payload, not identifiers.
- Copy [`pii-names.example.txt`](pii-names.example.txt) to `.local/pii-names.txt` and edit it. The `.local/` folder is gitignored in this repository for exactly this reason.

The script prints a warning when it runs without a names file. Treat that warning as a failure for anything you intend to share.

## Trust model — read the output

Detection is pattern-based and therefore imperfect. Two guards follow from that:

1. The report lists exactly what was replaced, so the redaction is reviewable rather than assumed.
2. `--strict` re-scans the **output** and exits non-zero if anything matching a high-risk pattern survived.

A script cannot certify that a document is safe. It can only remove what it recognises. **Open the `.sanitized.md` and read it before it goes anywhere.** Things it will not catch: a name spelled in a way not in your list, an account number printed with unusual separators, a scanned image (no text layer; OCR it locally first, never send the image to a cloud model), and free text in a memo field that describes you.

`--mapping FILE` writes the pseudonym-to-original table. That file contains the very data you are protecting. If you need it, write it under `.local/` and never share it.

## Where this fits in an assistant workflow

```
confirmation.pdf ──sanitize──▶ confirmation.sanitized.md ──you read it──▶ assistant (ghostfolio-updater)
                                        │
                                        └── redaction-report.json (counts, residual_clean: true)
```

The assistant works from the sanitized text: it resolves the symbol against what you hold, checks `quantity × price` against the stated total, checks for a duplicate, and proposes the activity. The one thing it needs that the sanitized text no longer carries — which Ghostfolio account the trade belongs to — is something *you* tell it by the account's Ghostfolio name, which is a label you chose and not an institution identifier.

## Test

```bash
python -m pytest sanitize/test_sanitize_pdf.py -q
```

The test builds a PDF stuffed with synthetic identifiers, including the cases that were once missed (a Luhn-invalid card number, a name inside an email local part, an IBAN partially eaten by the card rule, a short listed name eating part of an ordinary word, a listed birth date surviving because dates are protected), and asserts none of them survive. All identifiers in the test are invented.
