# Frontier Atlas open test surface

Offline, publishable protocol verifier candidate for Frontier Atlas bounded
claim–citation audits. It validates blind case packets, immutable source
snapshots, exact citation spans, case-bound human annotations, commitment and
reveal records, hidden qualification scoring, signed Git evidence, and
two-annotator agreement metrics.

This repository does **not** contain the closed judge, production prompts or
routing, private answer keys, raw pilot annotations, gold labels, holdout
content, user documents, provider integrations, or secrets. It has no remote
and is not approved for publication yet.

## Authority boundary

The verifier can establish that protocol records are internally consistent and
cryptographically bound. It cannot establish that a source is true, that a
GitHub account is one unique human, that omitted web evidence does not exist,
or that a model is production-safe. Public packets explicitly carry
`promotion_eligible=false` and `gold_authority=false`.

V1 accepts an explicit claim, immutable cited source or synthetic source text,
exact cited span, source metadata, and an optional bounded corpus. It does not
perform document segmentation or open-web retrieval.

## Requirements and install

- Python 3.11 or newer
- Git only for `identity verify-git`
- No runtime dependencies, network access, provider key, or account login

For an editable local install:

```powershell
py -3.11 -m pip install --no-deps -e .
atlas-test --json doctor
```

In an air-gapped environment that already has setuptools but not the `wheel`
build package, use the included compatibility shim without downloading
anything:

```powershell
py -3.11 setup.py develop
atlas-test --json doctor
```

Run the full offline verification without installing:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
```

## CLI map

```text
atlas-test doctor
atlas-test schemas list
atlas-test canonicalize --input VALUE.json [--out CANONICAL.json]
atlas-test packet validate --packet PACKET.json
atlas-test annotation validate --annotation ANNOTATION.json --packet PACKET.json
atlas-test salt generate --out SALT.txt
atlas-test commitment create --annotation ANNOTATION.json --packet PACKET.json \
  --salt-file SALT.txt --committed-at 2026-08-27T08:00:00Z --out COMMITMENT.json
atlas-test reveal create --commitment COMMITMENT.json --annotation ANNOTATION.json \
  --packet PACKET.json --salt-file SALT.txt --revealed-at 2026-08-27T09:00:00Z \
  --out REVEAL.json
atlas-test reveal verify --commitment COMMITMENT.json --reveal REVEAL.json \
  --packet PACKET.json
atlas-test qualification score --key PRIVATE_KEY.json --submission SUBMISSION.jsonl \
  --packet PACKET.json
atlas-test agreement score --annotations REVEALS.jsonl --packet PACKET.json \
  --strata PRIVATE_STRATA.jsonl
atlas-test identity verify-git --repo REPO --commit COMMIT
```

Place global `--json` before the command for one stable JSON object on stdout.
Success exits `0`, protocol or usage failure exits `2`, and unwrapped I/O
failure exits `3`. JSON mode never emits answer details from qualification
scoring. Unexpected internal failure exits `4` and emits no traceback or
partial protocol result.

## Documentation

- [Protocol and invariants](docs/PROTOCOL.md)
- [Human annotation guide](docs/ANNOTATION_GUIDE.md)
- [Contributor workflow](docs/CONTRIBUTOR_WORKFLOW.md)
- [Public/private boundary](PUBLIC_BOUNDARY.md)

Research baseline provenance: `frontier-atlas@0db3118`.
