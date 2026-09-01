# Frontier Atlas open test surface

This is the public exam paper for Frontier Atlas. It is not the product.

You can run the verifier offline and check that a test packet is internally
consistent. You cannot get a passing score, see the answer key, or run the
private judge from this repository.

What it checks, in plain terms: a claim, the exact span it cites, a frozen
source snapshot, and the commit/reveal records around a human annotation.

The product runtime, prompts, gold labels, holdout set, and secrets stay
private. This is the only public Frontier Atlas repository.

## Public-test status

This is a public **test surface**, not a product release and not an open-source
distribution. The current packets are blind, non-gold calibration candidates.
They cannot grant a model, contributor, or release a passing status.

- Inspect and run the verifier without network access or model API calls.
- Report reproducible protocol, packet, documentation, or verifier defects.
- Do not post hidden labels, private data, credentials, or vulnerability details.
- Read [the participation rules](CONTRIBUTING.md), [security policy](SECURITY.md),
  and [license notice](LICENSE) before participating.

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
- [Public-test participation](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Local calibration packets

- [`p4-semantic-pilot-v1`](packets/p4-semantic-pilot-v1/README.md): 64-case
  process-blind semantic calibration packet; human annotation has not started
  and the packet has no gold or promotion authority.
- [`p4-qualification-candidate-v1`](packets/p4-qualification-candidate-v1/README.md):
  inactive 12-case bilingual qualification candidate; private key review is
  pending and no score currently grants contributor status.

Research baseline provenance: `frontier-atlas@0db3118`.
