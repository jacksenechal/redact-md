"""Integration tests: exercise the real Presidio engine end to end.
Skipped automatically when en_core_web_lg is not installed."""
import pytest

pytestmark = pytest.mark.integration


def _model_available() -> bool:
    try:
        import spacy
        spacy.load("en_core_web_lg")
        return True
    except Exception:
        return False


needs_model = pytest.mark.skipif(
    not _model_available(), reason="en_core_web_lg not installed"
)


@needs_model
def test_redacts_pii_but_preserves_code():
    from redact_md import redact
    src = (
        "Alice Nguyen emailed a.nguyen@firm.com about SSN 432-18-6792.\n\n"
        "```\nkeep bob@example.com here\n```\n"
    )
    out = redact(src)
    assert "Alice Nguyen" not in out
    assert "a.nguyen@firm.com" not in out
    assert "432-18-6792" not in out
    assert "bob@example.com" in out          # code block untouched
    assert "<PERSON>" in out and "<EMAIL>" in out and "<SSN>" in out


@needs_model
def test_default_redacts_beyond_the_labeled_set():
    # Regression guard: the default must redact every type Presidio detects,
    # not just the 11 with custom labels. A leaked license is the failure
    # this tool exists to prevent.
    from redact_md import redact
    src = ("Driver license D1234567, wallet "
           "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.")
    out = redact(src)
    assert "D1234567" not in out                          # US_DRIVER_LICENSE
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" not in out # CRYPTO


@needs_model
def test_keep_disables_entity_type():
    from redact_md import redact
    src = "We met on March 3, 2026 to talk with Bob Jones."
    out = redact(src, keep={"DATE_TIME"})
    assert "March 3, 2026" in out             # DATE_TIME kept
    assert "Bob Jones" not in out             # PERSON still redacted


@needs_model
def test_entities_allowlist_limits_scope():
    from redact_md import redact
    src = "Call Bob Jones at bob@example.com."
    out = redact(src, entities=["EMAIL_ADDRESS"])
    assert "bob@example.com" not in out
    assert "Bob Jones" in out                 # PERSON not in allowlist, left alone
