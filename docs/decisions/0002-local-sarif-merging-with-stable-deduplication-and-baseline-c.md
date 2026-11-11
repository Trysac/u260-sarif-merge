# Local SARIF merging with stable deduplication and baseline comparison

Status: accepted (generated, pending human review)

## Context

Teams use multiple security scanners and upload each SARIF report separately, causing duplicate findings and unclear new-vs-baseline status. Code scanning platforms handle this only after upload, but local gates need a merged, de-duplicated log with baseline marks.

## Decision

Implement a Python package that merges SARIF 2.1.0 logs: runs grouped by tool driver name and version; rules merged in first-seen order (first definition wins); results de-duplicated using a stable SHA-256 key based on partialFingerprints or fallback to normalized location and message; artifact arrays and artifactLocation.index dropped; output sorted and tagged with sarifMerge properties. Also provide compare_baseline to mark results as new/unchanged/absent.

## Consequences

Produces one deterministic SARIF file suitable for PR gates. Deeper schema validation, SARIF 2.0/1.0 conversion, and fingerprint computation from source are out of scope. The output intentionally drops artifact indexes and arrays to preserve correctness after merging.
