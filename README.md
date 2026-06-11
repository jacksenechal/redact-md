# redact-md

Markdown in, redacted markdown out, code blocks left alone. All local.

`redact-md` strips PII (names, emails, phones, SSNs, IBANs, and more) from
markdown files using [Microsoft Presidio](https://github.com/microsoft/presidio)
and a local spaCy model. Nothing crosses the network. Fenced code blocks and
inline `` `code` `` are preserved unchanged, so it is safe to run on notes,
transcripts, and AI artifacts that mix prose with config and snippets.

```
**Alice Nguyen:** My SSN is 432-18-6792. Reach me at a.nguyen@firm.com.

```yaml
api_key: "sk-abc123"   # code blocks are skipped
```
```

becomes

```
**<PERSON>:** My SSN is <SSN>. Reach me at <EMAIL>.

```yaml
api_key: "sk-abc123"   # untouched
```
```

## Why this exists

Markdown is everywhere now: meeting transcripts, Obsidian vaults, and the trail
of artifacts that AI tools leave behind. A lot of it contains PII, and a lot of
it eventually gets pasted into a cloud model. The sane move is to scrub it
locally first.

Presidio does the hard part (detection) well, but there was no small CLI that
just cleans a file and hands it back. The closest thing,
[`presidio-cli`](https://github.com/insightsengineering/presidio-cli), is an
analyzer: it *reports* the PII it finds, like a linter, rather than emitting
cleaned text, and it is not markdown-aware. `redact-md` fills that gap: file in,
clean file out, code blocks intact.

## Benchmarks

Full methodology and numbers are in the
[accompanying blog post](https://jacksenechal.com). Short version:

| Tool | Recall | PERSON | ms/doc | Egress |
|------|--------|--------|--------|--------|
| redact-cli (CLI) | 40% | 0% | 21 ms | No |
| pii-vault | 53% | 0% | 7 ms | No |
| redact-cli (Docker+NER) | 65% | 84% | 339 ms | No |
| **Presidio (this tool)** | **90%** | **98%** | **64 ms** | **No** |
| opf (accuracy ceiling) | 95% | 96% | 20,000 ms | No |

Regex-only tools miss every person name. Presidio catches 98% of names, is
local, and is fast. The remaining gap versus the opf model ceiling is mostly
street addresses (Presidio: 38%, opf: 100%); for high-stakes documents, run
[opf](https://github.com/openai/privacy-filter) as a second pass.

## Install

Requires Python 3.10+. The `[model]` extra pulls in Presidio, spaCy, and the
`en_core_web_lg` model (~400 MB, one-time download):

```bash
pipx install "redact-md[model] @ git+https://github.com/jacksenechal/redact-md"
```

If you already manage the spaCy model yourself (or want to keep the base package
free of pinned model wheels), install the base package and download the model
separately:

```bash
pipx install git+https://github.com/jacksenechal/redact-md
python -m spacy download en_core_web_lg
```

`redact-md` will tell you exactly what to run if the model is missing.

## Usage

```bash
# Print redacted text to stdout
redact-md notes.md

# Write to a new file
redact-md notes.md -o notes_redacted.md

# Overwrite in place (saves original as notes.md.bak)
redact-md -i notes.md

# Read from stdin (handy as a filter or agent hook)
cat notes.md | redact-md -

# Redact an entire folder of .md files
redact-md --dir ~/meetings/2026-06/ --out-dir ~/meetings/2026-06-redacted/
```

### Choosing what to redact

By default `redact-md` redacts a fixed set of entity types, and *only* those
types (detection is restricted to the set, so nothing else is touched or
mislabeled). You can narrow or adjust it:

```bash
# List the supported entity types
redact-md --list-entities

# Keep dates/times (Presidio tags every date; often that's just noise)
redact-md --keep DATE_TIME notes.md

# Redact ONLY these types
redact-md --entities PERSON,EMAIL_ADDRESS notes.md
```

Default set: `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SSN`,
`CREDIT_CARD`, `IBAN_CODE`, `LOCATION`, `IP_ADDRESS`, `DATE_TIME`,
`MEDICAL_LICENSE`, `URL`. `--keep` and `--entities` are mutually exclusive.

### Use as an agent hook

Because it reads stdin and writes stdout, `redact-md` drops cleanly into a
pre-processing step. Pipe a file through it before any tool or prompt sends the
text to a cloud model, so PII is stripped before it ever leaves the machine.

## Known gaps

Street addresses (38% recall), phone numbers written as words
("five five five"), bare passwords with no nearby keyword, and some national
formats (sort codes, Swiss VAT IDs). For documents where addresses matter, run
[opf](https://github.com/openai/privacy-filter) as a second pass
(`opf redact --device cpu`).

## Security model

All inference is local. Presidio uses spaCy `en_core_web_lg`, installed as a pip
wheel, which never contacts the network at runtime. The optional Azure AI
recognizer (`azure_ai_language.py`) is not loaded by the default
`AnalyzerEngine()`. No telemetry.

## Benchmark harness

The `bench/` directory holds the 15-transcript labeled corpus, the evaluation
scripts, and the captured results behind the numbers above. The Presidio column
reproduces from this package alone:

```bash
pip install -e ".[dev,model]"
python bench/scripts/evaluate.py --tools presidio --save bench/results/my_run.json
```

The other columns need their respective tools present (the Rust `redact`
binary, the `ghcr.io/censgate/redact:full` image on a local port, and the `opf`
model), so treat those scripts as the exact harness used rather than a one-command repro.

## Development

```bash
git clone https://github.com/jacksenechal/redact-md
cd redact-md
python -m venv venv && source venv/bin/activate
pip install -e ".[dev,model]"
pytest                      # unit + integration (model present)
pytest -m "not integration" # fast, no model required
```

## License

MIT
