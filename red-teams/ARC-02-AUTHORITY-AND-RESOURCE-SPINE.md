# Arc 02 authority and resource spine red team

Status: executable source and compiler controls for the bounded Arc 02 foundation.

These cases test the new capability and observation primitives. They do not claim that current transport, session promotion, application delivery, or production allocation coverage has migrated.

## Run

```powershell
$arc02Target = "C:\Users\Admin\.allmystuff-sandbox-stage\myownmesh-v4-arc02-workspace-target"
python scripts/check-v4-arc02-spine.py
python scripts/check-v4-arc02-spine.py --negative-controls
python scripts/check-v4-arc02-compiler-boundaries.py
cargo test -p myownmesh-core --lib v4_arc02 --target-dir $arc02Target -j 16
cargo test -p myownmesh-core --doc --target-dir $arc02Target -j 16
```

The Python compiler check creates a temporary Cargo project, uses `cargo check --offline`, and starts no runtime binary. The focused Rust tests are in-process and use no listener or socket.

## Authority source mutations

The negative-control command injects each fault into an in-memory source copy and requires the gate to reject it:

- a public field, public mint, wrapped `Result<Self, _>` mint, or second inherent implementation;
- a protected type alias or renamed import;
- a raw identifier, parenthesized implementation target, or inherent `where` clause;
- a factory trait, `From`, `TryFrom`, or `Into` conversion;
- an alternate runtime constructor or `Default` implementation;
- production macro, code-generating attribute, or descendant owner module;
- a redirected crate-root module, conditional replacement module, or redirected Cargo library target;
- a renamed raw legacy extractor or wrapper trait such as `Deref`;
- a missing runtime witness, module export, boundary file, or compile-fail control.

The crate root and all seven authority-owner modules also have canonical production-token SHA-256 fingerprints. Any other production-token change fails closed until the fingerprint and semantic gate are reviewed together.

## Compiler rejection controls

The compiler harness proves one positive public type path and ten forbidden expressions:

- constructing a candidate or local principal from a public `String`;
- using a connected channel where a Session or authenticated channel is required;
- calling a public Session constructor;
- serializing, deserializing, or cloning a Session;
- substituting a pre-authentication permit for a Session permit;
- importing the crate-private runtime witness.

A rejection counts only when the Cargo target fails with the expected Rust error code, required type-specific diagnostic fragments, and a primary span on the marked probe line. The harness also proves that a wrong code, wrong fragment, or wrong line does not match.

## Resource mutations

The source controls also reject:

- a process-global resource accountant;
- resource policy, admission, permit, capability, networking, filesystem, or process behavior in the observer;
- changes to the closed pre-authentication and post-authentication family sets.

The focused tests cover all closed families, active and completed accounting, pre-authentication and post-authentication separation, adjustable observations, defensive underflow, overflow saturation, poisoned state recovery, and sticky inexact reporting.

## Pass meaning

A pass proves the checked source and compiler boundaries for this frozen scaffold. It does not prove production resource coverage, production Session promotion, or safety after arbitrary memory corruption. The Arc 02 report records those open gates.
