"""
Run opf via its Python API (single model load, then batch).
Must be run with the opf pipx Python:
  /home/jack/.local/pipx/venvs/opf/bin/python3 run_opf_api.py
"""
from __future__ import annotations
import sys
import time
import json
import difflib
from pathlib import Path
from dataclasses import dataclass
from typing import List

# Add corpus path
sys.path.insert(0, str(Path(__file__).parent.parent))
from transcripts.corpus import load_all, Span


def _overlaps(a, b) -> bool:
    return a.start < b.end and b.start < a.end


def _iou(a, b) -> float:
    inter_start = max(a.start, b.start)
    inter_end = min(a.end, b.end)
    if inter_end <= inter_start:
        return 0.0
    inter = inter_end - inter_start
    union = (a.end - a.start) + (b.end - b.start) - inter
    return inter / union if union > 0 else 0.0


def gold_hit(gold: Span, predicted: List[Span]) -> bool:
    for p in predicted:
        if _overlaps(gold, p) and _iou(gold, p) >= 0.3:
            return True
    return False


def safe_hit(safe: Span, predicted: List[Span]) -> bool:
    for p in predicted:
        if _overlaps(safe, p):
            return True
    return False


def redacted_to_spans(original: str, redacted: str) -> List[Span]:
    matcher = difflib.SequenceMatcher(None, original, redacted, autojunk=False)
    spans = []
    for op, o1, o2, n1, n2 in matcher.get_opcodes():
        if op in ("replace", "delete") and o2 > o1:
            spans.append(Span(o1, o2, "REDACTED", original[o1:o2]))
    return spans


def main():
    print("Loading opf model...", file=sys.stderr, flush=True)
    t_load_start = time.perf_counter()
    from opf import OPF
    opf_instance = OPF(device="cpu")
    # Force model load with a warm-up
    _ = opf_instance.redact("warm up")
    load_ms = (time.perf_counter() - t_load_start) * 1000.0
    print(f"Model loaded in {load_ms:.0f} ms", file=sys.stderr, flush=True)

    transcripts = load_all()
    print(f"Running on {len(transcripts)} transcripts...", file=sys.stderr, flush=True)

    per_doc_ms = []
    tp = fn = fp_safe = total_gold = total_predicted = 0
    per_label = {}
    misses = []
    safe_hits = []

    for t in transcripts:
        t0 = time.perf_counter()
        result = opf_instance.redact(t.content)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        per_doc_ms.append(elapsed_ms)
        print(f"  {t.name}: {elapsed_ms:.0f} ms", file=sys.stderr, flush=True)

        # Build predicted spans from redacted text
        redacted_text = result.redacted_text if hasattr(result, 'redacted_text') else str(result)

        # Try to use detected_spans if available
        predicted = []
        if hasattr(result, 'detected_spans') and result.detected_spans:
            for sp in result.detected_spans:
                predicted.append(Span(sp.start, sp.end, sp.label, sp.text))
        else:
            predicted = redacted_to_spans(t.content, redacted_text)

        total_gold += len(t.pii)
        total_predicted += len(predicted)

        for gold in t.pii:
            lbl = gold.label
            if lbl not in per_label:
                per_label[lbl] = {"tp": 0, "fn": 0, "total": 0}
            per_label[lbl]["total"] += 1
            if gold_hit(gold, predicted):
                tp += 1
                per_label[lbl]["tp"] += 1
            else:
                fn += 1
                per_label[lbl]["fn"] += 1
                misses.append(f"[{t.name}] [{lbl}] {gold.text!r}")

        for safe in t.safe:
            if safe_hit(safe, predicted):
                fp_safe += 1
                safe_hits.append(f"[{t.name}] {safe.text[:60]!r}")

    recall = tp / total_gold if total_gold else 0
    fp_apparent = max(0, total_predicted - tp)
    precision = tp / (tp + fp_apparent) if (tp + fp_apparent) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    avg_ms = sum(per_doc_ms) / len(per_doc_ms) if per_doc_ms else 0

    out = {
        "tool": "opf (CPU)",
        "tp": tp, "fn": fn, "fp_safe": fp_safe,
        "total_gold": total_gold, "total_predicted": total_predicted,
        "recall": recall, "precision": precision, "f1": f1,
        "load_ms": load_ms, "avg_ms": avg_ms,
        "per_doc_ms": per_doc_ms,
        "per_label": per_label,
        "misses": misses,
        "safe_hits": safe_hits,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
