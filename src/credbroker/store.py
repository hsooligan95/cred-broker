"""Simulated backing store: the 'real secrets' live here, and only here.

In a production broker this is a vault / cloud secrets manager behind
the tool-side shim. Here it is an in-memory dict of clearly synthetic
values. The broker's ``use`` path is the only way in, and what crosses
back to the caller is the *result of the tool's work* — the secret
itself is consumed inside this module's call, mirroring a shim that
exchanges a handle for a secret inside the tool's own process.
"""

from __future__ import annotations

# Synthetic demo values. Not real credentials for anything, anywhere.
SECRETS = {
    "db/factory/pumps": "SYNTHETIC-SECRET-pump-db-ro-0001",
    "db/factory/inventory": "SYNTHETIC-SECRET-inventory-db-ro-0002",
    "deploy/checkout-api": "SYNTHETIC-SECRET-deploy-token-0003",
}

# What the tool does with the secret once it has it: canned work results.
# (resource, action) -> result string the caller is allowed to see.
WORK_RESULTS = {
    ("db/factory/pumps", "read"): "pump P-104: operational, no maintenance hold",
    ("db/factory/inventory", "read"): "SKU-2211 gaskets: 14 in stock at plant store",
    ("deploy/checkout-api", "deploy"): "checkout-api deploy started (build 4821)",
}


class BackingStore:
    def perform(self, resource: str, action: str) -> str:
        """Use the resource's secret internally; return only the result."""
        secret = SECRETS.get(resource)
        if secret is None:
            raise KeyError(f"no secret held for resource {resource!r}")
        # The secret is 'used' here — e.g. presented to the real system
        # by the shim — and deliberately never leaves this call.
        _ = len(secret)
        try:
            return WORK_RESULTS[(resource, action)]
        except KeyError:
            raise KeyError(
                f"no work defined for ({resource!r}, {action!r})") from None
