# Public-test participation

Frontier Atlas is accepting reproducible reports against this public test
surface. Public testing does not expose or delegate product, gold-label,
promotion, qualification, or release authority.

## In scope

- protocol contradictions or ambiguous invariants;
- verifier behavior that differs from the documented protocol;
- malformed, biased, duplicated, or accidentally revealing public cases;
- offline reproducibility, cross-platform, CLI, schema, or documentation bugs;
- proposed adversarial cases that contain no private or copyrighted source data.

Open one issue per independently reproducible problem. Include the command,
expected behavior, actual behavior, operating system, Python version, packet ID,
and the smallest safe reproducer. State explicitly whether any network or model
API was used.

## Out of scope for public issues

Do not post credentials, personal or customer data, private repository content,
hidden labels, qualification answers, salts before reveal, sealed holdout data,
production prompts, provider transcripts, or vulnerability details. Follow
`SECURITY.md` for security reports.

Do not claim that a passing local run proves factual truth, production safety,
gold status, contributor qualification, or release readiness. Those conclusions
are outside the authority of this repository.

Source-code pull requests are paused during the initial public-test phase. This
keeps protocol reports separate from licensing and authority decisions. Use an
issue to propose a change; the owner may invite a narrowly scoped patch later.
