# Agent Passport — post-quantum agent identity and signed AI-decision receipts

This extension adds tools to issue and **independently verify** AI-agent passports and
AI-decision receipts signed with **ML-DSA-65 (NIST FIPS 204, security level 3)**.

The design goal is that verification requires no trust in the issuer: a receipt is checked
against a published signing-key directory, so anyone can confirm it offline without calling
FractalAI at all. Receipts can additionally be anchored write-once on-chain.

## Free tools (no payment, no key)

- `verify_passport` — verify an agent passport's ML-DSA-65 signature.
- `lookup_agent` — look up an agent in the on-chain FRC-55 registry.
- `list_fractalai_proofs` — list the available proof endpoints and their prices.
- `list_agents` — fetch the ML-DSA-65-signed index of registered agents and verify its signature offline against the notary key pinned in the package.
- `get_agent_manifest` — fetch an agent's signed manifest and verify it only against the agent's current key.
- `verify_agent_manifest` — verify a manifest JSON you were handed, offline.

## Paid tools (x402 micropayments, USDC on Base)

`issue_passport`, `witness_payment`, `seal_ml_dsa`, `notarize_decision`,
`prove_provenance`, `attest_training`, `seal_cbom`, `verify_agent_kya`, `verify_proof`.

Calling one of these without payment returns a standard x402 `PaymentRequired` response
describing the amount and the accepted payment methods. Nothing is charged implicitly, and
no wallet is required to use the free verification tools.

## How to verify our claims yourself

- Signing-key directory: <https://fractalai.net.co/.well-known/x402-receipt-keys>
- Paid endpoint catalogue: <https://fractalai.net.co/.well-known/x402.json>
- Offline verifier and on-chain anchor, MIT: <https://github.com/johnInarti/pqc-receipt-anchor>

## Honest scope

We implement FIPS 204 ML-DSA-65 (NIST security level 3). We are **not** FIPS 140-3 / CMVP
validated, **not** CNSA 2.0, and have had **no third-party security audit**. This is a
single-operator project running a single validator, with no paying customers yet. The part
that is independently checkable is the signature and the on-chain anchor, and you can check
both from the MIT sources above without relying on us.
