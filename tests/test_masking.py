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
