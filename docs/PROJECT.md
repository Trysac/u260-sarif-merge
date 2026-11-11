# Project record

## Objective

Merge SARIF 2.1.0 logs from several scanners into one: runs grouped by tool, rules merged with reindexed results, duplicates removed by fingerprint and baseline states marked

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested.
- Out of scope: anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 626299 / 73313 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.1050 |

## Factory run u260 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-11 | generation | deepseek-v4-pro | yes | 1676 | 27327 | 0 | 3328 | 0.0553 |
| 2026-11-11 | fix-1 | deepseek-flash | no | 17702 | 8475 | 0 | 209792 | 0.0084 |
| 2026-11-11 | audit | deepseek-flash | no | 20717 | 17408 | 0 | 210816 | 0.0142 |
| 2026-11-11 | fix-2 | deepseek-flash | no | 10494 | 4103 | 0 | 62336 | 0.0042 |
| 2026-11-11 | docs | deepseek-flash | no | 89182 | 16000 | 0 | 256 | 0.0230 |

Total: $0.1050. Prices: deepseek line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
