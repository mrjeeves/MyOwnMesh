# Architecture migration pull request checklist

## Scope

- Arc:
- Current source commit:
- State class moved:
- Old owner:
- New sole owner:

## Boundary

- New typed inputs:
- New typed outputs:
- Capability transition:
- Pre-auth resources:
- Post-auth resources:
- Forbidden responsibilities checked:

## Compatibility

- Compatibility adapter added or changed:
- Production callers redirected:
- Exact deletion arc:
- Legacy code deleted in this PR:

## Evidence

- Positive controls:
- Negative controls:
- Compile-time boundary tests:
- Unit/property tests:
- Integration tests:
- Red-team cases:
- Crash/fault cases:
- Performance/resource measurements:

## Architecture review

- Invariants exercised:
- Does this add a durable route or current-path concept? `No` required.
- Does this make transport optional or external to usable networking? `No` required.
- Does this add a state owner or global event/command grab bag? `No` required.
- Does any public ID become an internal capability? `No` required.
- Does any untrusted input cross promotion? `No` required.
- Does this add fixed codec, video/audio, screen/camera, or lane-count semantics to the basal core? `No` required.
- If connector-native real-time flow behavior changes, are session binding, pre-promotion quarantine, application ownership, compatibility deletion, and measured performance covered?

## Upstream

- Upstream classification, if applicable:
- Mechanism/test ported rather than legacy owner merged:

## Owner decisions

- Values or tradeoffs requiring review:
