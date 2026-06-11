"""
redact-md: markdown-aware local PII redaction using Presidio.

Fenced code blocks and inline `code` are preserved unchanged.
All analysis runs locally via spaCy en_core_web_lg -- no network egress.

Usage:
  redact-md notes.md                    # prints redacted text to stdout
  redact-md notes.md -o notes_clean.md  # writes to file
  redact-md -i notes.md                 # in-place (overwrites original)
  cat notes.md | redact-md -            # reads from stdin
  redact-md --dir ~/meetings/ --out-dir ~/meetings-redacted/
  redact-md --keep DATE_TIME notes.md   # redact everything except dates
  redact-md --names "Savannah Okafor,Will" notes.md   # always redact a roster
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple

from presidio_analyzer import AnalyzerEngine, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


_FENCED_BLOCK = re.compile(
    r"(?m)^(`{3,}[^\n]*\n.*?^`{3,}|~{3,}[^\n]*\n.*?^~{3,})",
    re.DOTALL,
)
_INLINE_CODE = re.compile(r"`[^`\n]+`")

_PFX = "\x00CODEBLOCK_"
_SFX = "\x00"

# Pretty replacement labels for the most common entity types. Any other
# entity Presidio detects is still redacted -- the anonymizer falls back to a
# generic <ENTITY_TYPE> tag for anything not listed here.
_OPERATORS = {
    "PERSON":        OperatorConfig("replace", {"new_value": "<PERSON>"}),
    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
    "PHONE_NUMBER":  OperatorConfig("replace", {"new_value": "<PHONE>"}),
    "US_SSN":        OperatorConfig("replace", {"new_value": "<SSN>"}),
    "CREDIT_CARD":   OperatorConfig("replace", {"new_value": "<CREDIT_CARD>"}),
    "IBAN_CODE":     OperatorConfig("replace", {"new_value": "<IBAN>"}),
    "LOCATION":      OperatorConfig("replace", {"new_value": "<LOCATION>"}),
    "IP_ADDRESS":    OperatorConfig("replace", {"new_value": "<IP>"}),
    "DATE_TIME":     OperatorConfig("replace", {"new_value": "<DATE>"}),
    "MEDICAL_LICENSE": OperatorConfig("replace", {"new_value": "<ID>"}),
    "URL":           OperatorConfig("replace", {"new_value": "<URL>"}),
}

# Presidio's default predefined recognizers for English. By default redact-md
# detects ALL of these (maximum recall); this tuple drives --list-entities and
# CLI validation. Detection itself uses whatever the installed Presidio version
# supports, so a newer Presidio that adds recognizers is still a superset.
SUPPORTED_ENTITIES = (
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "US_ITIN",
    "US_PASSPORT", "US_DRIVER_LICENSE", "US_BANK_NUMBER", "CREDIT_CARD",
    "IBAN_CODE", "CRYPTO", "IP_ADDRESS", "LOCATION", "DATE_TIME", "NRP",
    "MEDICAL_LICENSE", "UK_NHS", "URL",
)

_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None


def _engines() -> tuple[AnalyzerEngine, AnonymizerEngine]:
    global _analyzer, _anonymizer
    if _analyzer is None:
        try:
            _analyzer = AnalyzerEngine()
            _anonymizer = AnonymizerEngine()
        except Exception as exc:
            print(
                "redact-md: spaCy model 'en_core_web_lg' is not installed.\n"
                "Install it with:  python -m spacy download en_core_web_lg",
                file=sys.stderr,
            )
            print(f"  ({exc})", file=sys.stderr)
            sys.exit(1)
    return _analyzer, _anonymizer


def _mask_code(text: str) -> tuple[str, List[Tuple[str, str]]]:
    saved: List[Tuple[str, str]] = []

    def _sub(m: re.Match) -> str:
        ph = f"{_PFX}{len(saved)}{_SFX}"
        saved.append((ph, m.group(0)))
        return ph

    text = _FENCED_BLOCK.sub(_sub, text)
    text = _INLINE_CODE.sub(_sub, text)
    return text, saved


def _unmask_code(text: str, saved: List[Tuple[str, str]]) -> str:
    for ph, original in saved:
        text = text.replace(ph, original)
    return text


def redact(text: str, entities=None, keep=None, names=None) -> str:
    """Redact PII from ``text``, preserving code blocks.

    entities: allowlist of entity types to detect. ``None`` (the default)
              means detect everything Presidio supports -- maximum recall.
    keep:     iterable of entity types to leave untouched, applied after
              detection. Mutually exclusive with ``entities`` at the CLI.
    names:    iterable of known person names to always redact (as PERSON),
              matched case-insensitively. Use this for a meeting roster: it
              guarantees those names are caught even when NER misses them
              (bare first names, names that are also places or common words).
    """
    if entities is not None and not entities and not names:
        # An explicit empty allowlist means "redact nothing". (Presidio treats
        # an empty entities list as "detect everything", so short-circuit.)
        return text
    masked, saved = _mask_code(text)
    analyzer, anonymizer = _engines()

    ad_hoc = None
    active = entities
    if names:
        ad_hoc = [PatternRecognizer(supported_entity="PERSON", deny_list=list(names))]
        # A deny-list only helps if PERSON is actually being detected, so make
        # sure it survives an explicit --entities allowlist.
        if active is not None and "PERSON" not in active:
            active = list(active) + ["PERSON"]

    hits = analyzer.analyze(
        text=masked,
        language="en",
        entities=list(active) if active is not None else None,
        ad_hoc_recognizers=ad_hoc,
    )
    if keep:
        keep = set(keep)
        hits = [h for h in hits if h.entity_type not in keep]
    if not hits:
        return text
    result = anonymizer.anonymize(text=masked, analyzer_results=hits, operators=_OPERATORS)
    return _unmask_code(result.text, saved)


def _redact_file(src: Path, dst: Path, entities=None, keep=None, names=None) -> None:
    dst.write_text(
        redact(src.read_text(encoding="utf-8"), entities=entities, keep=keep, names=names),
        encoding="utf-8",
    )
    print(f"{src} -> {dst}", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser(
        prog="redact-md",
        description="Redact PII from markdown files locally (Presidio + spaCy).",
    )
    p.add_argument("input", nargs="?", metavar="FILE",
                   help="Markdown file to redact, or '-' for stdin. Prints to stdout.")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write output to FILE instead of stdout.")
    p.add_argument("-i", "--in-place", action="store_true",
                   help="Overwrite FILE in place (takes a backup to FILE.bak).")
    p.add_argument("--dir", metavar="DIR",
                   help="Redact all .md files under DIR recursively.")
    p.add_argument("--out-dir", metavar="DIR",
                   help="Output directory for --dir mode (required).")
    p.add_argument("--keep", metavar="ENTITIES",
                   help="Comma-separated entity types to NOT redact (everything else is still redacted).")
    p.add_argument("--entities", metavar="ENTITIES",
                   help="Comma-separated allowlist: redact ONLY these types.")
    p.add_argument("--list-entities", action="store_true",
                   help="Print the supported entity types and exit.")
    p.add_argument("--names", metavar="NAMES",
                   help="Comma-separated known person names to always redact, e.g. a "
                        "meeting roster. Matched case-insensitively; guarantees names "
                        "the model would otherwise miss (bare first names, names that "
                        "are also places or common words).")
    p.add_argument("--names-file", metavar="FILE",
                   help="File with one name per line to always redact (merged with "
                        "--names; blank lines and lines starting with # are ignored).")
    args = p.parse_args()

    if args.list_entities:
        for name in sorted(SUPPORTED_ENTITIES):
            print(name)
        return

    if args.keep and args.entities:
        p.error("--keep and --entities are mutually exclusive")

    def _parse_entities(raw: str) -> list[str]:
        result = []
        for name in raw.split(","):
            name = name.strip().upper()
            if not name:
                continue
            if name not in SUPPORTED_ENTITIES:
                p.error(f"unknown entity type: {name} (see --list-entities)")
            result.append(name)
        return result

    # entities = allowlist (detect only these); keep = drop these after
    # detection. Default (neither) redacts every type Presidio detects.
    entities: list[str] | None = _parse_entities(args.entities) if args.entities else None
    keep: set[str] | None = set(_parse_entities(args.keep)) if args.keep else None

    # names = a deny-list of known people to always redact as PERSON.
    names: list[str] = []
    if args.names:
        names += [n.strip() for n in args.names.split(",") if n.strip()]
    if args.names_file:
        names += [ln.strip() for ln in
                  Path(args.names_file).read_text(encoding="utf-8").splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")]
    names = names or None

    if args.dir:
        if not args.out_dir:
            p.error("--out-dir is required with --dir")
        in_root = Path(args.dir)
        out_root = Path(args.out_dir)
        out_root.mkdir(parents=True, exist_ok=True)
        for src in sorted(in_root.rglob("*.md")):
            dst = out_root / src.relative_to(in_root)
            dst.parent.mkdir(parents=True, exist_ok=True)
            _redact_file(src, dst, entities=entities, keep=keep, names=names)
        return

    if not args.input:
        p.error("provide a FILE argument or --dir")

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text(encoding="utf-8")

    redacted = redact(text, entities=entities, keep=keep, names=names)

    if args.in_place and args.input != "-":
        src = Path(args.input)
        src.with_suffix(src.suffix + ".bak").write_text(
            src.read_text(encoding="utf-8"), encoding="utf-8"
        )
        src.write_text(redacted, encoding="utf-8")
        print(f"Redacted in place: {src} (backup: {src}.bak)", file=sys.stderr)
    elif args.output:
        Path(args.output).write_text(redacted, encoding="utf-8")
    else:
        sys.stdout.write(redacted)
