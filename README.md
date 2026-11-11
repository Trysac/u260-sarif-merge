# trysac-sarif-merge

Merge SARIF 2.1.0 logs from multiple scanners into one de-duplicated log with baseline states.

[![CI](https://github.com/Trysac/u260-sarif-merge/workflows/CI/badge.svg)](https://github.com/Trysac/u260-sarif-merge/actions)
[![PyPI version](https://badge.fury.io/py/trysac-sarif-merge.svg)](https://badge.fury.io/py/trysac-sarif-merge)

## Installation

```bash
pip install trysac-sarif-merge
```

## Usage

### Python API

```python
from sarif_merge import load_sarif, merge, compare_baseline

with open("a.sarif") as f:
    log_a = load_sarif(f.read())
with open("b.sarif") as f:
    log_b = load_sarif(f.read())
merged = merge([log_a, log_b])
print(merged["runs"][0]["properties"]["sarifMerge"])
```

### Command line

```bash
sarif-merge merge a.sarif b.sarif --output merged.sarif
sarif-merge baseline current.sarif baseline.sarif --output compared.sarif --fail-on-new
```

Consult the [documentation](docs/) for further details.
