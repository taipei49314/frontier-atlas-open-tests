# Contributor workflow

This is the offline workflow for a qualified pilot contributor. Actual packet
assignment, private qualification keys, and reveal timing remain controlled by
the private authority repository.

## 1. Verify the packet

```powershell
atlas-test --json packet validate --packet packet.json
```

Confirm the reported packet ID, case count, source count, and hashes against the
assignment notice. Stop if validation fails or the packet identity differs.

## 2. Produce and validate an annotation

Follow `ANNOTATION_GUIDE.md`, then validate the annotation against the entire
packet so its case hash and anchors are checked:

```powershell
atlas-test --json annotation validate `
  --annotation annotation.json `
  --packet packet.json
```

## 3. Create salt and commitment

Keep the salt private until reveal. Both files refuse overwrite.

```powershell
atlas-test --json salt generate --out private\assignment.salt
atlas-test --json commitment create `
  --annotation annotation.json `
  --packet packet.json `
  --salt-file private\assignment.salt `
  --committed-at 2026-08-27T08:00:00Z `
  --out commitment.json
```

Commit the commitment record using the required signed Git identity. Do not
commit the annotation or salt at this stage.

## 4. Reveal only after both commitments lock

```powershell
atlas-test --json reveal create `
  --commitment commitment.json `
  --annotation annotation.json `
  --packet packet.json `
  --salt-file private\assignment.salt `
  --revealed-at 2026-08-27T09:00:00Z `
  --out reveal.json

atlas-test --json reveal verify `
  --commitment commitment.json `
  --reveal reveal.json `
  --packet packet.json
```

The private coordinator must verify both contributors’ signed commitments were
locked before accepting either reveal. The CLI verifies cryptographic records;
it does not enforce social timing or unique-human identity by itself.

## 5. Private scoring

Qualification keys, assignment strata, raw reveals, and adjudication remain
private. Only aggregate qualification and agreement reports may be considered
for later publication, after an explicit disclosure review.
