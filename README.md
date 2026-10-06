# did:moltrust conformance vectors

Executable checks against the published [did:moltrust method
specification](https://moltrust.ch/did-method-spec.html). Each vector names the
section it comes from, the outcome the specification requires, and the
machine-readable reason code the answer has to carry.

Apache-2.0. Anyone may run these against our live services; that is the point.

## Why this exists

Over two days in October 2026, eleven defects turned up in the gap between
published prose and hand-written implementation. Every one was found from outside
or by accident:

- A Universal Resolver maintainer reported that `did:moltrust:ambassador0001`
  came back as an internal error of ours. Two separate causes, neither watched.
- Sections 4.3 and 4.4 document two endpoints. One answers 404 because the path
  in the document is wrong; the other does not exist in any form.
- Section 4.4 says a deactivated DID document is marked `deactivated: true`. It
  is not, so a W3C resolver sees a revoked agent as a valid one.
- Section 2.2 says the identifier is derived from the agent's Ed25519 public
  key. No code path does that; all 532 registered identifiers come from
  `uuid.uuid4()`.
- The agent card advertises seven extension URIs. All seven answer 404, and an
  external crawler dereferenced one of them.

On 2026-05-30 an audit found nine read endpoints enforcing the write pattern on a
path DID and fixed all nine. The tenth, `/identity/resolve/{did}`, was missed:
the audit's list was built from the endpoints that *called a validator*, and that
one compared inline. It kept answering wrongly for four more months and was found
from outside. **The fix was a list, so the next instance was not covered. A
vector is not a list.**

## What is covered

| Section | What | Vectors |
|---|---|---|
| 2.2 | syntax of the method-specific identifier: length, case, hex, the `ext_` prefix | 14 |
| 2.2 | the derivation clause — the identifier from the first 8 bytes of SHA-256 over the Ed25519 public key | 2 |
| 4.2 | resolution outcomes: a document, `did_not_found`, `invalidDid`, an unknown method | 14 |
| 6 | the cross-ecosystem bridge, `POST /identity/bridge-simple` | 1 |

A resolution vector names exactly one target, the registry API or the Universal
Resolver driver, so a failure against one cannot be excused by a register entry
that belongs to the other.

## Running

```sh
python3 tools/build_vectors.py --check      # vectors/ matches the table
python3 tools/run_vectors.py                # everything
python3 tools/run_vectors.py --check syntax # one kind
MOLTRUST_API=https://api.moltrust.ch \
MOLTRUST_DRIVER=https://uresolver.moltrust.ch \
  python3 tools/run_vectors.py --json out.json
```

Standard library only. Exit status: `0` everything held or is registered, `1` a
new deviation or a registered one that disappeared, `2` the run could not be
carried out — a target that cannot be reached is a run condition, not a verdict
about conformance.

## The register

`deviations.json` holds the deviations we already know about. Each entry carries
where it lives, when it was first seen, and one sentence of cause. Four entries
say outright that the cause is not established, rather than pretending to one.

- An entry with `status: open` is **reported and does not fail the run**.
- A deviation with no entry **fails the run**.
- An `observable: true` entry whose vector starts holding is reported and the
  entry is closed.
- An `observable: false` entry is a defect in a document. No run can close it,
  because a sentence missing from a specification is not something a runner can
  watch fail.

The derivation vector is in here although it fails for every identifier we have
issued. That is deliberate: a vector that only ever passes measures nothing.

## Relation to the other repositories

`MoltyCel/aae-conformance-vectors` covers the Agent Authorization Envelope. This
one covers the DID method, and follows its layout: vectors as JSON with an
expected result, a schema, a generator, and a runner.
