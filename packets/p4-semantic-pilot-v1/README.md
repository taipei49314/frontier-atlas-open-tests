# P4 semantic pilot v1

This 64-case packet calibrates the annotation rubric, blind workflow,
commit–reveal tooling, and inter-annotator agreement reporting.

It contains all 16 candidate-v2 cases plus a private, balanced selection of 48
incubator cases. Source case IDs, candidate labels, attack/control status,
severity, trap metadata, slice IDs, pair IDs, and model outputs are absent.
Cases use opaque assignment and case references; the mapping stays in the
private authority repository.

The underlying synthetic/candidate content already exists in the public
research baseline. This is therefore `content_blinded_public_source`, not a
strictly unpublished test. Searching the baseline or using prior labels breaks
annotator independence. The packet is non-gold and cannot support product
promotion, source-truth, retrieval-completeness, or document-segmentation
claims.

Validate before annotation:

```powershell
atlas-test --json packet validate --packet packet.json
```

Human annotation has not started. A valid packet only proves structural and
byte-level integrity; it does not create labels or a PASS.
