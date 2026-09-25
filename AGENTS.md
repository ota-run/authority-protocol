<!--
                █████
               ░░███
       ██████  ███████    ██████
      ███░░███░░░███░    ░░░░░███
     ░███ ░███  ░███      ███████
     ░███ ░███  ░███ ███ ███░░███
     ░░██████   ░░█████ ░░████████
      ░░░░░░     ░░░░░   ░░░░░░░░

   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.

   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.

   Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
   You may not use this file except in compliance with the License.
   Unless required by applicable law or agreed to in writing, software distributed under the
   License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
   either express or implied. See the License for the specific language governing permissions
   and limitations under the License.

   If you need additional information or have any questions, please email: os@ota.run
-->

# AGENTS.md — ota-authority-protocol

> Scope: AI-agent operating guide for this repo. `ota.yaml` is the execution
> contract source of truth; this file only explains how to work inside it.
> If they conflict, `ota.yaml` is authoritative and CI must consume it.

## 1. What this repo is

Canonical, provider-neutral wire protocol for Ota crossing authority
(`library`, crate `ota-authority-protocol`). Single-crate source of versioned
message model, framing rules, semantic identity helpers, and conformance
vectors used by Ota Core, trusted launchers, and independently operated
brokers.

Cross-repo conformance exists only when Core + Launcher pin and test the same
immutable revision. A locally green suite here proves this crate's structure
and vectors — not deployment, signing-key authority, broker persistence,
protected-store loading, provider contact, execution, or cleanup.

See `README.md` (boundary, wire sequence, runtime-boundary attestation,
production launcher records, consume/verify) and `CHANGELOG.md` (additive
record history).

## 2. Contract and toolchain (do not improvise)

- Contract: `ota.yaml` — project `ota-authority-protocol`, Ota minimum
  `1.6.26`, `execution.preferred/supported: native`.
- Rust `1.95.0` via `rust-toolchain.toml` (`minimal` + `clippy` + `rustfmt`),
  edition `2024`, `rust-version = "1.95"`.
- Always resolve the runnable lane first:

  ```sh
  ota tasks --safe --use
  ota run verify --agent
  ```

- CI (`./.github/workflows/ci.yml`, `ubuntu-24.04`): installs
  contract-selected Ota via `ota-run/setup` (`source: contract`), verifies
  exact source identity (`ota --version --json` must be `source_build=true`,
  `dirty=false`, commit prefix-matches contract rev), then runs
  `ota run verify --agent`.
- Agent surface (`ota.yaml:agent`): `entrypoint: verify`,
  `default_task: verify`, `safe_tasks: [fmt, check, clippy, test, verify]`,
  `verify_after_changes: [verify]`.

## 3. Layout

```text
src/lib.rs        # protocol types, constants, framing, identities, and tests
Cargo.toml        # library only; no bins, no features
ota.yaml          # contract: fmt/check/clippy/test/verify (no --all-features here)
README.md         # boundary + wire + attestation + launcher records + pin recipe
CHANGELOG.md      # Unreleased documents every additive record
rust-toolchain.toml
.github/workflows/ci.yml
```

Dependencies are intentionally tiny: `base64`, `serde` (+derive),
`serde_jcs`, `serde_json`, `semver`, `sha2`, `thiserror`. Do not add transport,
crypto-issuer, filesystem, time, or async runtimes — this crate defines bytes
and identities, it does not open stores, sign, verify policy, persist, or
execute.

## 4. Canonical verification (use this, nothing else, for routine work)

`verify` aggregates `fmt → check → clippy → test`.

```sh
ota run verify --agent
```

- No `--all-features`: this crate has no features. Do not add the flag and do
  not invent features to gate protocol truth.
- Always `--locked`. `fmt` is read-only verification; never run `cargo fmt`
  (write) unless explicitly intended and reviewed.
- Tests cover framing, canonical serialization, identities, compatibility, and
  adversarial vectors. They do not issue authority, consume leases, or execute
  governed tasks — never present them as deployment evidence.

## 5. Safe vs. forbidden for agents

Writable through the routine agent surface: `src`, `README.md`, `CHANGELOG.md`,
`Cargo.toml`, `rust-toolchain.toml`.

Protected from routine agent execution: `.github`, `AGENTS.md`, `Cargo.lock`,
`ota.yaml`, `LICENSE`. Change these only when the user explicitly requests the
governance, dependency, or licensing edit, and review the result separately.

Safe lanes: `fmt`, `check`, `clippy`, `test`, `verify` via
`ota run <task> --agent`.

Forbidden:

- editing the protocol pin by branch, floating a dependency, or hand-editing
  `Cargo.lock`;
- invoking launcher/systemd/broker/attestor/history binaries, protected
  stores (`/etc/ota/*`, `/var/lib/ota/*`, `/run/ota/*`), `sudo`/`systemctl`,
  or Core execution to "prove" a protocol change;
- claiming a local `verify` proves launcher deployment, broker authority,
  provider contact/delivery, execution approval, receipt/archive validity, or
  cleanup.

## 6. Protocol rules agents must respect

- **Ownership:** this repo owns version/message-kind constants, exact
  serialized request/attestation/decision/lease/consumption types, additive
  v2/v3/v4 attestation + capability/snapshot/secret-delivery/history records,
  closed launcher/job-principal/systemd profiles, `4-byte big-endian length +
  ≤64 KiB UTF-8 JSON` framing, JCS + SHA-256 identities, compatibility +
  adversarial vectors.
- **Non-ownership:** no contracts, scope derivation, admission policy, signing
  keys, replay persistence, signature-verification policy, store loading,
  approval workflows, broker persistence/transport credentials, execution,
  receipt creation, archive storage, or semantic archive verification. Those
  stay with Core / launcher / broker.
- **Immutability + additive versioning:** never mutate a released shape,
  domain string, identity domain, or profile identity. Add a new
  `..._V2/V3/V4` record, new `message_kind`, new domain constant, new profile
  ID instead. V1 attestation shape and v1/v2/v3 response domains are frozen.
- **Structural conventions:**
  - `#[serde(deny_unknown_fields)]` on every serialized struct;
  - fixed `message_kind` + `protocol_version`/`schema_version` fields;
  - domain separation: identity domains end in `\0` (`...\.v1\0`), signature
    domains are `.../.../vN` strings — copy exactly, never normalize;
  - profile identities are content-addressed `sha256:...` constants — never
    recompute by hand, never substitute across profiles (e.g. systemd
    v1/v2/v3/v4 and job-principal v1/v2 are distinct);
  - bounded limits (`MAX_FRAME_BYTES`, `MAX_LAUNCHER_*`, history/capability
    ceilings) are wire truth — changing them is a compatibility change.
- **Compatibility change rule:** changing a pinned `rev`, message kind,
  framing, identity derivation, required observation set, or profile bytes
  requires Core + Launcher to repin and revalidate the same immutable rev
  together. Consumers pin exact revs:
  `ota-authority-protocol = { git = "...", rev = "<40-hex>" }` — never a branch.
- **No authority inflation:** a structurally valid projection/bundle/snapshot
  is not authority, not provider contact/delivery, not execution approval, not
  receipt/assurance. Keep doc language structural ("defines", "reconciles")
  vs. runtime ("proves deployment", "contacts provider") precise.

## 7. Code conventions

- Keep the Ota ASCII-banner + `Copyright (C) 2026 — 2026, Ota` + Apache-2.0 +
  `os@ota.run` header on every file. Do not alter/remove it.
- `cargo fmt` style; `clippy -D warnings` clean.
- One crate, flat `lib.rs`: keep constants grouped (versions → profiles →
  paths → limits → message kinds → identity domains → signature domains →
  structs → helpers → tests). Avoid splitting into modules unless the
  maintainers ask — diff reviewability of the single wire file matters.
- Every new wire record needs: constants (kind + identity/signature domains),
  struct(s) with `deny_unknown_fields`, canonical identity helper, positive +
  negative/adversarial conformance vectors (missing/substituted/reordered/
  unknown-field/replay/wrong-domain cases must refuse).
- Update `README.md` (boundary/wire/profile sections) and `CHANGELOG.md`
  (Unreleased, one bullet per additive record with what it does *and* what it
  explicitly does not do) with every protocol change.

## 8. Security

- Never add keys, credentials, tokens, provider responses, paths, or file
  content to wire records unless the existing closed record already carries
  that field by design (most capability/projection records deliberately exclude
  them — keep it that way).
- Nonce/commitment, freshness windows, and replay/mutation rules are load-bearing:
  preserve exact field names, bounds (e.g. 5-min challenge lifetimes), and
  request↔response identity reconciliation.
- Report suspected protocol confusion/downgrade issues privately to
  `os@ota.run` with rev, repro, and the bypassed claim. No secrets in reports.

## 9. Before opening a PR

1. `ota tasks --safe --use`, then `ota run verify --agent`.
2. Review every intentional protected-path change separately. Confirm no new
   dependency outside the minimal set without justification, no released shape
   was mutated, vectors cover downgrade/substitution, `README` + `CHANGELOG`
   are updated, and headers remain intact.
3. If consumers must repin: state the old → new immutable rev, which
   Core/Launcher revs were revalidated, and that branch pins were not used.
4. CI is `ubuntu-24.04` `verify` only — cross-repo PID-1/systemd pressure lives
   in `authority-launcher` + Core and is owned by administrators, not this PR.

## 10. References

- `README.md` — boundary, 7-message authority sequence + history/completion
  sequences, v1/v2/v3 attestation, systemd launcher records, pin recipe.
- `CHANGELOG.md`, `ota.yaml`, `Cargo.toml`, `rust-toolchain.toml`,
  `.github/workflows/ci.yml`.
- Consumers: `ota-run/authority-launcher` (privileged launcher side),
  `ota-run/ota` (Core: scope/admission/execution/evidence), operator ref
  `Broker Crossing Authority` (`ota.run/docs/reference/broker-crossing-authority`).

<!-- ota-generated-agent-guidance:start -->
# AGENTS.md

Generated from `./ota.yaml` by `ota agents`.

## Repo

- `project`: `ota-authority-protocol`
- `description`: `Canonical wire protocol and conformance model for Ota crossing authority`

## Default Workflow

- `name`: `verify`
- `intent`: `verification`
- `run`: `ota run verify`

## Agent Contract

Use only declared `ota run <task>` paths. If the contract does not model the work you need, stop and request a contract update; do not bypass the agent boundary with raw package-manager, compiler, or test commands.

- `entrypoint`: `verify` (`ota run verify`)
- `default_task`: `verify` (`ota run verify`)
- `safe_tasks`:
  - `fmt` (`ota run fmt`)
  - `check` (`ota run check`)
  - `clippy` (`ota run clippy`)
  - `test` (`ota run test`)
  - `verify` (`ota run verify`)
- `verify_after_changes`:
  - `verify` (`ota run verify`)
- `writable_paths`: `src`, `README.md`, `CHANGELOG.md`, `Cargo.toml`, `rust-toolchain.toml`
- `protected_paths`: `.github`, `AGENTS.md`, `Cargo.lock`, `ota.yaml`, `LICENSE`

## Bootstrap

This contract is verified against the immutable Ota Core revision below; do not replace it with a branch or ambient binary in review or CI.

- `source.kind`: `git_rev`
- `source.rev`: `63297ad95ef156b335a1dfb54090146406077a3f`
- `sh`: `curl -fsSL https://dist.ota.run/install.sh | OTA_GIT_REV=63297ad95ef156b335a1dfb54090146406077a3f sh -s -- --from-git`
- `powershell`: `$env:OTA_GIT_REV='63297ad95ef156b335a1dfb54090146406077a3f'; & ([scriptblock]::Create((irm https://dist.ota.run/install.ps1))) -FromGit`

## Notes

Start with `ota tasks --safe --use`, then use `ota run verify --agent` after source changes.
If Ota does not report a lane callable, stop; do not drop `--agent` or invoke Cargo directly.
This repository owns protocol structure and conformance, not repository admission, broker
authority, protected-store loading, signing keys, provider contact, or governed execution.

Keep message kinds, identity domains, framing, and compatibility records review-bound across
Ota Core and authority-launcher. Do not use a locally passing protocol suite as evidence that
a launcher, broker, protected runner, or provider boundary is deployed or authorized.
<!-- ota-generated-agent-guidance:end -->
