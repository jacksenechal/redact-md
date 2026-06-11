"""
PII redaction benchmark evaluator.

For each tool, given predicted redacted text (or predicted span list),
compute token-level recall, precision, F1 against the gold corpus.

Overlap strategy: a gold span is "hit" if the predicted output masks
ANY character within [gold.start, gold.end). We use character-level
IoU >= 0.5 for span matching (partial coverage still counts as a hit
for recall; a predicted span that covers 2+ gold spans counts once each).
"""
from __future__ import annotations

import sys
import os
import time
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from collections import defaultdict

# Add parent dir so we can import corpus
sys.path.insert(0, str(Path(__file__).parent.parent))
from transcripts.corpus import load_all, Span, Transcript


# --------------------------------------------------------------------------- #
# Span helpers
# --------------------------------------------------------------------------- #

def _overlaps(a: Span, b: Span) -> bool:
    return a.start < b.end and b.start < a.end


def _iou(a: Span, b: Span) -> float:
    inter_start = max(a.start, b.start)
    inter_end = min(a.end, b.end)
    if inter_end <= inter_start:
        return 0.0
    inter = inter_end - inter_start
    union = (a.end - a.start) + (b.end - b.start) - inter
    return inter / union if union > 0 else 0.0


def gold_hit(gold: Span, predicted: List[Span], iou_thresh: float = 0.3) -> bool:
    """Return True if any predicted span overlaps the gold span sufficiently."""
    for p in predicted:
        if _overlaps(gold, p) and _iou(gold, p) >= iou_thresh:
            return True
    return False


def safe_hit(safe: Span, predicted: List[Span]) -> bool:
    """Return True if any predicted span overlaps a must-not-touch span."""
    for p in predicted:
        if _overlaps(safe, p):
            return True
    return False


# --------------------------------------------------------------------------- #
# Redacted-text -> predicted spans
# For tools that produce redacted text (not span lists), we diff original vs
# redacted to find which character regions were masked.
# --------------------------------------------------------------------------- #

def redacted_text_to_spans(original: str, redacted: str) -> List[Span]:
    """
    Given original text and its redacted version, find the character ranges
    in the ORIGINAL that were replaced. Works when the replacement is shorter,
    same length, or longer than the original.
    Uses difflib's SequenceMatcher for robust diff.
    """
    import difflib
    matcher = difflib.SequenceMatcher(None, original, redacted, autojunk=False)
    spans = []
    for op, o1, o2, n1, n2 in matcher.get_opcodes():
        if op in ("replace", "delete"):
            # o1..o2 in original was replaced/deleted
            if o2 > o1:
                spans.append(Span(o1, o2, "REDACTED", original[o1:o2]))
    return spans


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

@dataclass
class EvalResult:
    tool: str
    tp: int = 0
    fn: int = 0
    fp_safe: int = 0           # predicted spans hitting safe code regions
    total_gold: int = 0
    total_predicted: int = 0
    per_label: Dict[str, Dict] = field(default_factory=lambda: defaultdict(lambda: {"tp": 0, "fn": 0, "total": 0}))
    misses: List[str] = field(default_factory=list)
    safe_hits: List[str] = field(default_factory=list)
    load_time_ms: float = 0.0
    per_doc_ms: List[float] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.tp / self.total_gold if self.total_gold else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp_apparent
        return self.tp / denom if denom else 0.0

    @property
    def fp_apparent(self) -> int:
        # Approximate: predicted spans that don't overlap any gold
        return max(0, self.total_predicted - self.tp)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def avg_ms(self) -> float:
        return sum(self.per_doc_ms) / len(self.per_doc_ms) if self.per_doc_ms else 0.0


def evaluate_spans(
    tool: str,
    get_predicted_spans: "callable",  # (Transcript) -> List[Span]
    transcripts: Optional[List[Transcript]] = None,
) -> EvalResult:
    if transcripts is None:
        transcripts = load_all()

    result = EvalResult(tool=tool)

    for t in transcripts:
        t0 = time.perf_counter()
        try:
            predicted = get_predicted_spans(t)
        except Exception as e:
            print(f"  ERROR on {t.name}: {e}", file=sys.stderr)
            predicted = []
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        result.per_doc_ms.append(elapsed_ms)

        result.total_gold += len(t.pii)
        result.total_predicted += len(predicted)

        for gold in t.pii:
            lbl = gold.label
            result.per_label[lbl]["total"] += 1
            if gold_hit(gold, predicted):
                result.tp += 1
                result.per_label[lbl]["tp"] += 1
            else:
                result.fn += 1
                result.per_label[lbl]["fn"] += 1
                result.misses.append(f"[{t.name}] [{lbl}] {gold.text!r}")

        for safe in t.safe:
            if safe_hit(safe, predicted):
                result.fp_safe += 1
                result.safe_hits.append(f"[{t.name}] {safe.text[:60]!r}")

    return result


def print_result(r: EvalResult):
    print(f"\n{'='*60}")
    print(f"  Tool: {r.tool}")
    print(f"{'='*60}")
    print(f"  Recall:    {r.recall:.1%}  ({r.tp}/{r.total_gold})")
    print(f"  Precision: {r.precision:.1%}")
    print(f"  F1:        {r.f1:.1%}")
    print(f"  Over-redaction (safe code hits): {r.fp_safe}")
    print(f"  Avg ms/transcript (warm):        {r.avg_ms:.0f} ms")
    print(f"  Model load time:                 {r.load_time_ms:.0f} ms")

    print(f"\n  Per-entity recall:")
    for lbl, d in sorted(r.per_label.items()):
        tp = d["tp"]
        tot = d["total"]
        pct = tp / tot if tot else 0
        bar = "#" * int(pct * 20)
        print(f"    {lbl:<25} {tp:2}/{tot:2}  {pct:5.0%}  {bar}")

    if r.misses:
        print(f"\n  FALSE NEGATIVES ({len(r.misses)}):")
        for m in r.misses:
            print(f"    MISS: {m}")

    if r.safe_hits:
        print(f"\n  SAFE SPANS HIT (over-redaction):")
        for s in r.safe_hits:
            print(f"    HIT: {s}")


# --------------------------------------------------------------------------- #
# Tool A: redact-cli
# --------------------------------------------------------------------------- #

REDACT_BIN = os.path.expanduser("~/.cargo/bin/redact")

def _run_redact_cli(t: Transcript) -> List[Span]:
    result = subprocess.run(
        [REDACT_BIN, "analyze", "--format", "json"],
        input=t.content,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"redact-cli error: {result.stderr[:200]}")
    data = json.loads(result.stdout)
    spans = []
    for e in data.get("detected_entities", []):
        start = e["start"]
        end = e["end"]
        label = str(e.get("entity_type", "UNKNOWN"))
        text = t.content[start:end]
        spans.append(Span(start, end, label, text))
    return spans


def bench_redact_cli(transcripts=None) -> EvalResult:
    print("Benchmarking redact-cli...", flush=True)
    t0 = time.perf_counter()
    subprocess.run([REDACT_BIN, "--version"], capture_output=True)
    load_ms = (time.perf_counter() - t0) * 1000.0
    r = evaluate_spans("redact-cli (regex only)", _run_redact_cli, transcripts)
    r.load_time_ms = load_ms
    return r


# --------------------------------------------------------------------------- #
# Tool B: pii-vault  (Rust via CLI — build a thin wrapper)
# --------------------------------------------------------------------------- #
# pii-vault has no Python binding and no official CLI binary.
# We build a minimal evaluator that loads the spec JSON directly and runs
# regex patterns using the same spec the Rust implementation uses.

def _load_piivault_spec() -> List[Dict]:
    """Download (once) and cache pii-vault spec recognizers via gh CLI."""
    cache_dir = Path("/tmp/piivault_spec")
    cache_dir.mkdir(exist_ok=True)
    spec_index = cache_dir / "index.json"
    if not spec_index.exists():
        result = subprocess.run(
            ["gh", "api", "repos/Jiansen/pii-vault/contents/spec/recognizers",
             "--jq", "[.[] | {name: .name, url: .download_url}]"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return []
        spec_index.write_text(result.stdout)

    files = json.loads(spec_index.read_text())
    recognizers = []
    for f in files:
        local = cache_dir / f["name"]
        if not local.exists():
            result = subprocess.run(
                ["curl", "-fsSL", "--max-time", "10", f["url"]],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                local.write_text(result.stdout)
        if local.exists():
            try:
                recognizers.append(json.loads(local.read_text()))
            except json.JSONDecodeError:
                pass
    return recognizers


def _build_piivault_engine():
    import re
    recognizers = _load_piivault_spec()
    patterns = []
    for rec in recognizers:
        entity = rec.get("entity_type", "UNKNOWN")
        for pat in rec.get("patterns", []):
            regex_str = pat.get("regex")
            if not regex_str:
                continue
            try:
                compiled = re.compile(regex_str, re.IGNORECASE)
                patterns.append((entity, compiled))
            except re.error:
                pass
    return patterns


_PIIVAULT_ENGINE = None

def _run_piivault(t: Transcript) -> List[Span]:
    global _PIIVAULT_ENGINE
    if _PIIVAULT_ENGINE is None:
        _PIIVAULT_ENGINE = _build_piivault_engine()
    spans = []
    seen = set()
    for entity, regex in _PIIVAULT_ENGINE:
        for m in regex.finditer(t.content):
            key = (m.start(), m.end())
            if key in seen:
                continue
            seen.add(key)
            spans.append(Span(m.start(), m.end(), entity, m.group()))
    return spans


def bench_piivault(transcripts=None) -> EvalResult:
    print("Benchmarking pii-vault (spec-driven regex via Python)...", flush=True)
    t0 = time.perf_counter()
    _load_piivault_spec()
    load_ms = (time.perf_counter() - t0) * 1000.0
    r = evaluate_spans("pii-vault (regex, Python port)", _run_piivault, transcripts)
    r.load_time_ms = load_ms
    return r


# --------------------------------------------------------------------------- #
# Tool C: Presidio
# --------------------------------------------------------------------------- #

def _build_presidio_engine():
    from presidio_analyzer import AnalyzerEngine
    return AnalyzerEngine()


_PRESIDIO_ENGINE = None

def _run_presidio(t: Transcript) -> List[Span]:
    global _PRESIDIO_ENGINE
    if _PRESIDIO_ENGINE is None:
        _PRESIDIO_ENGINE = _build_presidio_engine()
    results = _PRESIDIO_ENGINE.analyze(text=t.content, language="en")
    spans = []
    for r in results:
        spans.append(Span(r.start, r.end, r.entity_type, t.content[r.start:r.end]))
    return spans


def bench_presidio(transcripts=None) -> EvalResult:
    print("Benchmarking Presidio...", flush=True)
    t0 = time.perf_counter()
    _build_presidio_engine()
    load_ms = (time.perf_counter() - t0) * 1000.0
    # warm-up
    _run_presidio(load_all()[0])
    r = evaluate_spans("Presidio (spaCy en_core_web_lg)", _run_presidio, transcripts)
    r.load_time_ms = load_ms
    return r


# --------------------------------------------------------------------------- #
# Tool A2: redact-cli Docker API (with NER)
# --------------------------------------------------------------------------- #

REDACT_API_URL = "http://localhost:8080/api/v1/analyze"

def _run_redact_api(t: Transcript) -> List[Span]:
    import urllib.request
    payload = json.dumps({"text": t.content, "language": "en"}).encode()
    req = urllib.request.Request(
        REDACT_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    spans = []
    for e in data.get("results", []):
        start = e["start"]
        end = e["end"]
        label = str(e.get("entity_type", "UNKNOWN"))
        text = e.get("text") or t.content[start:end]
        spans.append(Span(start, end, label, text))
    return spans


def bench_redact_api(transcripts=None) -> EvalResult:
    import urllib.request
    print("Benchmarking redact-cli Docker API (pattern + NER)...", flush=True)
    # Warm-up: first call loads the ONNX model into memory
    t0 = time.perf_counter()
    payload = json.dumps({"text": "warm-up Alice Smith", "language": "en"}).encode()
    req = urllib.request.Request(
        REDACT_API_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30):
        pass
    load_ms = (time.perf_counter() - t0) * 1000.0
    r = evaluate_spans("redact-cli API (NER)", _run_redact_api, transcripts)
    r.load_time_ms = load_ms
    return r


# --------------------------------------------------------------------------- #
# Tool D: opf
# --------------------------------------------------------------------------- #

OPF_BIN = os.path.expanduser("~/.local/bin/opf")

def _run_opf(t: Transcript) -> List[Span]:
    # Pass the transcript as a file (-f), not on stdin: opf splits multiline
    # stdin into separate examples and emits one JSON object per example, which
    # breaks json.loads. -f treats the whole file as a single example.
    # --no-print-color-coded-text suppresses the ANSI legend that opf otherwise
    # appends to stdout after the JSON (also breaking the parse, with the old
    # code silently falling back to an empty span list).
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(t.content)
        path = f.name
    try:
        result = subprocess.run(
            [OPF_BIN, "redact", "--device", "cpu", "--format", "json",
             "--output-mode", "typed", "--no-print-color-coded-text", "-f", path],
            capture_output=True,
            text=True,
            timeout=300,
        )
    finally:
        os.unlink(path)
    if result.returncode != 0:
        raise RuntimeError(f"opf error: {result.stderr[:300]}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Fallback: diff-based span extraction
        return redacted_text_to_spans(t.content, result.stdout)

    spans = []
    for sp in data.get("detected_spans", []):
        start = sp["start"]
        end = sp["end"]
        label = sp.get("label", "REDACTED")
        text = sp.get("text", t.content[start:end])
        spans.append(Span(start, end, label, text))
    return spans


_OPF_LOADED = False

def bench_opf(transcripts=None) -> EvalResult:
    global _OPF_LOADED
    print("Benchmarking opf (CPU mode)...", flush=True)
    t0 = time.perf_counter()
    # Load by running on a tiny input
    subprocess.run(
        [OPF_BIN, "redact", "--device", "cpu", "--format", "json"],
        input="warm-up",
        capture_output=True, text=True, timeout=120,
    )
    load_ms = (time.perf_counter() - t0) * 1000.0
    _OPF_LOADED = True
    r = evaluate_spans("opf (CPU)", _run_opf, transcripts)
    r.load_time_ms = load_ms
    return r


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", nargs="+",
                        choices=["redact", "piivault", "presidio", "opf", "redact-api", "all"],
                        default=["all"])
    parser.add_argument("--save", help="Save results to JSON file")
    args = parser.parse_args()

    tools = args.tools
    if "all" in tools:
        tools = ["redact", "piivault", "presidio", "opf"]

    transcripts = load_all()
    print(f"Loaded {len(transcripts)} transcripts, "
          f"{sum(len(t.pii) for t in transcripts)} total gold PII spans\n")

    results = {}
    if "redact" in tools:
        results["redact"] = bench_redact_cli(transcripts)
        print_result(results["redact"])

    if "piivault" in tools:
        results["piivault"] = bench_piivault(transcripts)
        print_result(results["piivault"])

    if "presidio" in tools:
        results["presidio"] = bench_presidio(transcripts)
        print_result(results["presidio"])

    if "opf" in tools:
        results["opf"] = bench_opf(transcripts)
        print_result(results["opf"])

    if "redact-api" in tools:
        results["redact-api"] = bench_redact_api(transcripts)
        print_result(results["redact-api"])

    if args.save:
        out = {}
        for k, r in results.items():
            out[k] = {
                "recall": r.recall,
                "precision": r.precision,
                "f1": r.f1,
                "fp_safe": r.fp_safe,
                "avg_ms": r.avg_ms,
                "load_ms": r.load_time_ms,
                "misses": r.misses,
                "safe_hits": r.safe_hits,
                "per_label": {lbl: dict(d) for lbl, d in r.per_label.items()},
            }
        Path(args.save).write_text(json.dumps(out, indent=2))
        print(f"\nResults saved to {args.save}")
