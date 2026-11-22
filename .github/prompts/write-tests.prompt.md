---
mode: agent
description: Write tests for a named module in cred-broker
---

Write tests for the module I name, following this repo's existing test
style, layout, and fixtures. Cover the behavior the module documents,
including these invariants where they apply:

- Verification is fail-closed and ordered: signature -> expiry -> revocation -> agent binding -> scope. Never reorder or skip a step.
- Grant = intersection of the ask with the agent's policy ceiling; every cut is recorded — scope-down is a feature, not an error.
- The real secret is consumed inside the tool-side call only and never crosses back to the agent; the leak-check test must keep passing.

Then run the test suite:

    PYTHONPATH=src python3 -m unittest discover -s tests

Show the result. Do not claim done unless the suite is green; if a
test cannot pass, say why instead of weakening the assertion.
