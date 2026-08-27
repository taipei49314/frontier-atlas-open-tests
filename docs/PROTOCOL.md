# Frontier Atlas open-test protocol v1

Protocol identifier: `frontier-atlas-open-test-v1`
Canonicalization identifier: `atlas-canonical-json-v1`

## 1. What this protocol proves

The protocol proves structural and byte-level statements:

1. a packet contains exactly the declared cases and source manifests;
2. each real-source case cites content bytes and an exact span present in an
   immutable source snapshot;
3. each annotation binds the canonical hash of one exact case;
4. semantic and counterevidence anchors occur in the bound inputs;
5. a commitment predates its reveal and binds annotation, case, contributor,
   assignment, and salt;
6. qualification and agreement scores use complete, non-duplicated assignment
   coverage.

It does not prove world truth, source credibility, unique-human identity,
retrieval completeness, model quality, or production eligibility.

## 2. Canonical JSON

Canonical values are UTF-8 JSON with object keys sorted, no insignificant
whitespace, and no ASCII escaping requirement. Duplicate keys, floating-point
numbers, NaN, infinity, and unsupported host values are rejected. Integers are
allowed. Unicode strings are preserved as supplied; the verifier does not apply
Unicode normalization.

`canonical_sha256(value)` is SHA-256 over those canonical UTF-8 bytes. File
hashes are SHA-256 over exact file bytes, not parsed values. A semantically
equivalent file with different whitespace therefore has the same canonical
value hash but a different file hash.

## 3. Packet and source binding

A packet manifest binds `cases.jsonl` and, when present, `sources.jsonl` by
exact file hash and row count. Paths must remain inside the packet directory.
Unknown fields fail validation.

For a real-source case:

- `source_snapshot_id` and `source_span_id` are mandatory;
- `source_text` must equal the immutable UTF-8 snapshot content exactly;
- quote offsets must equal the declared exact source span;
- every cited or bounded-corpus snapshot must be bundled;
- every bundled source must be referenced by at least one case.

Synthetic calibration cases set both source identifiers to null and carry no
bounded corpus. This keeps synthetic semantic work separate from source-truth
or retrieval claims.

## 4. Annotation binding

Every annotation includes `case_sha256`. Linked validation recomputes the
canonical case hash, requires matching assignment identity, and verifies each
anchor occurrence against the exact case fields.

The citation-support layer covers exactly 11 dimensions:

`subject`, `predicate`, `object`, `scope`, `quantity`, `time`, `condition`,
`modality`, `attribution`, `causality`, and `polarity`.

Any verdict other than `entails` must set `unsafe_to_clear=true`. An unsafe
annotation cannot produce `overall=no_objection`. Unverified or conflicting
source provenance also cannot produce `no_objection`.

## 5. Bounded counterevidence

`exact_citation_only` means no corpus scan was requested. It must report
`scan_status=not_requested`, an empty scanned-snapshot list, null conflict
result, and no conflict anchors. This state must never be rendered as “no
counterevidence exists.”

`bounded_corpus` is limited to snapshot IDs supplied by the case:

- `complete` must list every bounded snapshot;
- `partial` must list a non-empty proper subset;
- `unavailable` cannot claim a conflict result;
- conflict anchors bind snapshot ID, character offsets, and exact snippet;
- bounded-corpus `no_objection` requires a complete scan and
  `conflicts_found=false`.

The protocol makes no claim about evidence outside that corpus.

## 6. Commit and reveal

Commitments use the domain `frontier-atlas-annotation-commit-v1`. The digest is
the canonical hash of an object containing the full annotation, assignment ID,
contributor ID, domain, and a 32–256 character URL-safe random salt. Because the
annotation contains `case_sha256`, the commitment also binds the exact case.

Commitment output omits annotation and salt. Salt files and commitment outputs
are created exclusively and refuse overwrite. Reveal verification checks the
entire commitment record hash, timestamps, identities, salt, annotation digest,
and linked packet case.

Git commit signatures are separate evidence. Offline verification can prove a
valid signature and signer fingerprint but reports GitHub account mapping as
`not_verified_offline`.

## 7. Qualification

A private key manifest binds an answer JSONL file by hash. Submission
annotations must cover the same assignments as both the key and the bound
qualification packet, with one contributor identity. Output contains only
aggregate basis-point scores, critical counts, thresholds, and pass/fail. It
never returns answer-level differences.

## 8. Agreement and gates

Agreement requires exactly two different contributors for every packet case.
All annotations are linked to packet cases before scoring.

The preregistered P4 gates are:

- overall verdict Cohen’s kappa at least 8,000 basis points;
- high/critical `unsafe_to_clear` raw agreement at least 9,500 basis points;
- overall multi-label violation macro F1 at least 8,000 basis points.

Violation F1 is computed per label over the two annotators, then averaged only
across labels with at least one positive annotation. All-negative labels are
`not_measured`; they cannot inflate the macro score. Kappa is `not_measured`
when its expected-agreement denominator is zero.

Severity and slice metadata stay in a private strata JSONL file. Without it,
the high/critical gate is `not_measured` and `all_gates_pass=false`. Language,
profile, severity, and overlapping slice denominators are reported separately,
but these P4 diagnostics do not grant promotion authority.

## 9. Public packet restrictions

Public packets must declare that labels, model outputs, attack metadata,
severity, and pair IDs are absent and that the assignment map remains private.
They must also declare `promotion_eligible=false` and `gold_authority=false`.
These constants are enforced by the executable validator, not only by JSON
Schema.
