---
mode: agent
description: Review the current diff against cred-broker's invariants
---

Review my current diff against this repo's invariants:

- Verification is fail-closed and ordered: signature -> expiry -> revocation -> agent binding -> scope. Never reorder or skip a step.
- Grant = intersection of the ask with the agent's policy ceiling; every cut is recorded — scope-down is a feature, not an error.
- The real secret is consumed inside the tool-side call only and never crosses back to the agent; the leak-check test must keep passing.
- The clock is injected, so demo-output.txt is byte-stable: regenerate it in the same change whenever behavior changes.

Flag every violation with file and line. Also flag any change that
alters a documented behavior contract (output shapes, exit codes,
event schemas, recorded artifacts) without updating the docs and
tests that describe it. No style nitpicks — correctness and contract
violations only.
