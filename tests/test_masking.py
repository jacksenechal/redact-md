"""
Unit tests for code-block masking logic.
No spaCy model required -- the Presidio engine is not instantiated.
"""
import pytest
from redact_md import _mask_code, _unmask_code


FENCED_YAML = """\
Before.

```yaml
host: alice@internal
key: secret-value
```

After.
"""

FENCED_PYTHON = """\
Text with `inline code` here.

```python
payload = b'\\x90' * 100
sock.connect(('10.0.0.1', 4444))
```

More text.
"""

NESTED_BACKTICKS = "Use ``double backticks`` or `single` inline code."

TILDE_FENCE = """\
Before.

~~~bash
echo $SECRET
~~~

After.
"""


def round_trip(text):
    masked, saved = _mask_code(text)
    return _unmask_code(masked, saved)


def test_fenced_block_preserved():
    masked, saved = _mask_code(FENCED_YAML)
    assert "alice@internal" not in masked
    assert "secret-value" not in masked
    assert len(saved) == 1


def test_fenced_block_restores():
    assert round_trip(FENCED_YAML) == FENCED_YAML


def test_inline_code_preserved():
    masked, saved = _mask_code(FENCED_PYTHON)
    assert "10.0.0.1" not in masked
    assert "`inline code`" not in masked


def test_inline_code_restores():
    assert round_trip(FENCED_PYTHON) == FENCED_PYTHON


def test_tilde_fence_preserved():
    masked, _ = _mask_code(TILDE_FENCE)
    assert "SECRET" not in masked


def test_tilde_fence_restores():
    assert round_trip(TILDE_FENCE) == TILDE_FENCE


def test_double_backtick_inline_code():
    masked, saved = _mask_code(NESTED_BACKTICKS)
    assert "double backticks" not in masked
    assert "single" not in masked
    assert " or " in masked                  # prose between spans stays prose
    assert round_trip(NESTED_BACKTICKS) == NESTED_BACKTICKS


def test_backtick_inside_double_backtick_span():
    masked, saved = _mask_code("Type ``a ` b`` here.")
    assert saved == [(saved[0][0], "``a ` b``")]


def test_longer_fence_not_closed_by_shorter_one():
    # A ```` block that shows a ``` line must not close there; if it did, the
    # closing ```` would open a new block and swallow the prose after it.
    text = "````\n```\n````\n\nCall Alice at alice@example.com.\n\n```\nls\n```\n"
    masked, saved = _mask_code(text)
    assert "alice@example.com" in masked
    assert len(saved) == 2
    assert round_trip(text) == text


def test_info_string_line_does_not_close_fence():
    text = "```\nsee ```python below\n```python\nx = 1\n```\nAfter.\n"
    masked, saved = _mask_code(text)
    assert "After." in masked
    assert round_trip(text) == text


def test_crlf_fence_preserved():
    text = "Before.\r\n```\r\nsecret\r\n```\r\nAfter.\r\n"
    masked, _ = _mask_code(text)
    assert "secret" not in masked
    assert round_trip(text) == text


def test_no_code_unchanged():
    text = "Hello world, no code blocks here.\n"
    masked, saved = _mask_code(text)
    assert masked == text
    assert saved == []


def test_multiple_blocks():
    text = "A\n```\nblock1\n```\nB\n```\nblock2\n```\nC"
    masked, saved = _mask_code(text)
    assert "block1" not in masked
    assert "block2" not in masked
    assert len(saved) == 2
    assert round_trip(text) == text


def test_prose_between_blocks_survives():
    text = "```\ncode\n```\nThis prose has john@example.com in it.\n```\nmore code\n```\n"
    masked, _ = _mask_code(text)
    assert "john@example.com" in masked


def test_placeholder_uniqueness():
    text = "```\nfirst\n```\n`second`\n```\nthird\n```\n"
    masked, saved = _mask_code(text)
    placeholders = [ph for ph, _ in saved]
    assert len(placeholders) == len(set(placeholders))


def test_empty_allowlist_redacts_nothing():
    # An explicit empty allowlist short-circuits before the engine loads, so
    # this runs without the spaCy model. Guards against Presidio's quirk of
    # treating entities=[] as "detect everything".
    from redact_md import redact
    text = "Bob Jones at bob@example.com."
    assert redact(text, entities=[]) == text
