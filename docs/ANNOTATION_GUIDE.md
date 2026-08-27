# Human annotation guide

This guide is for bounded claim–citation audits. Annotate only the supplied
claim, exact citation, adjacent context, source metadata, and optional bounded
corpus. Do not infer that the packet contains every relevant source.

## Decision order

1. Confirm the assignment and case opened correctly.
2. Compare the claim and evidence across all 11 dimensions.
3. Choose the citation verdict and blocking violations.
4. Record source provenance, credibility, and corroboration separately.
5. If a bounded corpus was requested, record exactly what was scanned and any
   byte-anchored conflict.
6. Set the overall outcome. When evidence is missing or ambiguous, fail closed
   to `human_review` or `unavailable`.

## Citation verdicts

- `entails`: the cited material supports the claim without a material semantic
  expansion or contradiction.
- `partial_support`: some proposition is supported, but at least one material
  dimension is stronger, missing, or unsupported.
- `contradicts`: the evidence explicitly conflicts with a material dimension.
- `insufficient_context`: the supplied span and adjacent context do not permit
  a determination.
- `ambiguous`: more than one materially different reading remains plausible.
- `abstain`: the annotator cannot responsibly decide under the rubric.

Only `entails` may set `unsafe_to_clear=false`. `partial_support` is not a soft
pass.

## The 11 dimensions

- `subject`: who or what the statement is about.
- `predicate`: the action, state, or relation asserted.
- `object`: the target or complement of the predicate.
- `scope`: population, geography, product, document section, or other bounds.
- `quantity`: amount, rate, comparison, threshold, or direction of magnitude.
- `time`: date, duration, sequence, recency, or forecast horizon.
- `condition`: prerequisite, exception, scenario, or qualifier.
- `modality`: certainty, possibility, obligation, recommendation, or intent.
- `attribution`: speaker, author, organization, or reported viewpoint.
- `causality`: causal claim versus correlation, sequence, or association.
- `polarity`: affirmation, negation, exclusion, or reversal.

Use `not_applicable` only when the claim genuinely has no such dimension; it
must carry no anchors. `not_expressed` means the claim expresses the dimension
but the evidence does not. `claim_stronger` and `claim_weaker` compare the claim
to the evidence, never the reverse.

## Anchors

An anchor is evidence for the annotation decision, not a paraphrase. Copy an
exact snippet from the designated field and use a zero-based occurrence index
when the same snippet appears more than once. Keep anchors as short as possible
while preserving the decisive wording.

For bounded-corpus conflicts, record the source snapshot ID, exact character
start and end offsets, and the exact snippet. The verifier rejects invented or
misaligned anchors.

## Source assurance

Citation support and source assurance are independent. A source can accurately
support a false claim, and a credible source can be cited for a claim it does
not support.

- Provenance asks whether the captured bytes and origin are verified.
- Credibility asks about the source’s authority for this subject.
- Corroboration asks whether the bounded evidence agrees or conflicts.

Use `not_assessed` rather than guessing. Never turn one credible source into a
claim of universal truth.

## Counterevidence

If no bounded corpus is provided, select `exact_citation_only` and
`not_requested`. This does not mean “none found.”

For a bounded corpus, distinguish:

- `complete`: every supplied snapshot was inspected;
- `partial`: only the listed proper subset was inspected;
- `unavailable`: the scan could not produce a result;
- `not_requested`: the bounded scan was not performed.

Any conflict result must be anchored. A partial or unavailable scan cannot
support bounded-corpus `no_objection`.

## Independence

Do not view another annotator’s answer, commitment salt, model output, hidden
label, severity, attack metadata, pair identity, or adjudication before reveal.
Commit your own completed annotation first. Agreement is diagnostic; majority
vote and model vote never create gold.
