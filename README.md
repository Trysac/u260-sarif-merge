# sarif-merge

[![PyPI version](https://img.shields.io/pypi/v/trysac-sarif-merge)](https://pypi.org/project/trysac-sarif-merge/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-sarif-merge)](LICENSE)
[![CI](https://github.com/Trysac/u260-sarif-merge/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u260-sarif-merge/actions/workflows/ci.yml)

Merge SARIF 2.1.0 logs from several scanners into one: runs grouped by tool, rules merged with reindexed results, duplicates removed by fingerprint and baseline states marked

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-sarif-merge
# or
uv add trysac-sarif-merge
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import sarif_merge

# normalize() trims surrounding whitespace and lower-cases the text.
print(sarif_merge.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    sarif_merge.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
