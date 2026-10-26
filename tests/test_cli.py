"""
Unit tests for the placeholder guardrail and CLI error handling.
No spaCy model required: the analyzer is faked, and the CLI errors fire
before the engine loads.
"""
import sys

import pytest
from presidio_analyzer import RecognizerResult
from presidio_anonymizer import AnonymizerEngine

import redact_md
from redact_md import RedactionError, main, redact


class _FakeAnalyzer:
    """Returns one fixed hit, standing in for a model-backed detection."""

    def __init__(self, entity_type, find, length):
        self.entity_type, self.find, self.length = entity_type, find, length

    def analyze(self, text, **_):
        start = text.index(self.find)
        return [RecognizerResult(self.entity_type, start, start + self.length, 0.9)]


def _use_analyzer(monkeypatch, analyzer):
    monkeypatch.setattr(redact_md, "_engines", lambda: (analyzer, AnonymizerEngine()))


def test_swallowed_code_span_fails_loudly(monkeypatch):
    # A URL glued to inline code: the detected span runs over the placeholder,
    # so the code would vanish from the output. It must raise instead.
    text = "See https://example.com/`snippet` for details."
    url_plus_placeholder = len("https://example.com/") + len("\x00CODEBLOCK_0\x00")
    _use_analyzer(monkeypatch, _FakeAnalyzer("URL", "https://", url_plus_placeholder))
    with pytest.raises(RedactionError, match="URL"):
        redact(text)


def test_code_span_next_to_hit_is_restored(monkeypatch):
    text = "See https://example.com/ and `snippet` here."
    _use_analyzer(monkeypatch, _FakeAnalyzer("URL", "https://", len("https://example.com/")))
    assert redact(text) == "See <URL> and `snippet` here."


def _run_cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["redact-md", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    return exc.value.code


def test_missing_input_is_one_line_error(monkeypatch, tmp_path):
    code = _run_cli(monkeypatch, str(tmp_path / "nope.md"))
    assert isinstance(code, str) and code.startswith("redact-md: ")
    assert "No such file" in code and "\n" not in code


def test_non_utf8_input_is_one_line_error(monkeypatch, tmp_path):
    bad = tmp_path / "bad.md"
    bad.write_bytes(b"\xff\xfe not utf-8")
    code = _run_cli(monkeypatch, str(bad))
    assert code.startswith(f"redact-md: {bad}: not valid UTF-8")


def test_missing_names_file_is_one_line_error(monkeypatch, tmp_path):
    src = tmp_path / "a.md"
    src.write_text("hello\n", encoding="utf-8")
    code = _run_cli(monkeypatch, "--names-file", str(tmp_path / "roster.txt"), str(src))
    assert "No such file" in code


def test_missing_dir_is_rejected(monkeypatch, tmp_path, capsys):
    assert _run_cli(monkeypatch, "--dir", str(tmp_path / "nope"),
                    "--out-dir", str(tmp_path / "out")) == 2
    assert "not a directory" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["-i", "-o", "out.md", "in.md"], ["-i", "-"]])
def test_in_place_conflicts_are_rejected(monkeypatch, argv):
    assert _run_cli(monkeypatch, *argv) == 2
