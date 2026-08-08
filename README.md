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

# Ota Authority Protocol

Canonical, provider-neutral wire protocol for Ota crossing authority.

This crate publishes the stable message model, framing rules, semantic identity helpers, and
foundation vectors intended for Ota Core, trusted launchers, and independently operated authority
brokers. Cross-repository conformance becomes established only when those consumers pin and test
the same immutable crate revision.

## Boundary

This repository owns:

- protocol version and message-kind constants;
- exact serialized request, attestation, decision, lease, and consumption types;
- additive runtime-boundary attestation v2 types and canonical protected-launcher profiles;
- immutable principal-mapping, Ota process-posture, and systemd launcher-profile foundations for
  the planned production protected-launcher adapter;
- bounded four-byte big-endian framing;
- JCS plus SHA-256 message identities; and
- compatibility and adversarial conformance tests.

It does not own repository contracts, semantic-scope derivation, admission policy, signing keys,
approval workflows, broker persistence, transport credentials, execution, receipts, or archives.
Those remain with Ota Core, the authority launcher, and the chosen broker implementation.

## Wire sequence

```mermaid
sequenceDiagram
    autonumber
    participant Core as Ota Core
    participant Launcher as Trusted launcher
    participant Broker as Authority broker

    Core->>Core: Freeze contract, semantic scope, work unit, and nonce commitment
    Core->>Launcher: challenge_request
    Launcher->>Broker: Relay framed challenge
    Broker-->>Launcher: attestation_response (signed)
    Launcher-->>Core: Relay signed attestation
    Core->>Core: Verify challenge, scope, work unit, origin, and freshness

    Core->>Launcher: authorization_request
    Launcher->>Broker: Relay exact-scope request
    Broker-->>Launcher: authorization_decision (signed)
    Launcher-->>Core: Relay signed decision

    alt Authorization is allowed
        Broker-->>Launcher: lease_issuance (signed)
        Launcher-->>Core: Relay signed one-use lease
        Core->>Core: Create pending crossing transaction
        Core->>Launcher: lease_consume
        Launcher->>Broker: Atomically validate and consume lease
        Broker-->>Launcher: lease_consume_response (signed)
        Launcher-->>Core: Relay transaction-bound consumption result
        alt Lease is verified as consumed
            Core->>Core: Execute only the exact authorized work unit
        else Consumption is refused or ambiguous
            Core->>Core: Refuse before governed execution
        end
    else Authorization is denied, stale, or ambiguous
        Core->>Core: Refuse before governed execution
    end

    opt Consume acknowledgement is uncertain
        Core->>Launcher: Fresh challenge_request
        Launcher-->>Core: Fresh attestation_response (signed)
        Core->>Launcher: lease_consumption_query
        Launcher->>Broker: Query exact prior consume request
        Broker-->>Launcher: lease_consumption_status (signed)
        Launcher-->>Core: Relay status and original signed consume response when consumed
        Core->>Core: Finalize old work unit as incomplete; never resume its execution
    end
```

The seven wire messages, in order, are `challenge_request`, `attestation_response`,
`authorization_request`, `authorization_decision`, `lease_issuance`, `lease_consume`, and
`lease_consume_response`. Recovery adds `lease_consumption_query` and
`lease_consumption_status`. Ota may execute the governed work unit only after it verifies a signed
`lease_consume_response` bound to the pending crossing transaction. Recovery never resumes that
old work unit: it reconciles the broker result, finalizes the abandoned local transaction as
incomplete, and requires a new authorization for any later execution.

## Runtime-boundary attestation

The original `LauncherAttestationPayload` and v1 response domain remain immutable. They prove a
fresh launcher session bound to the challenge, work unit, and semantic scope, but they do not prove
strong runtime separation.

The additive `LauncherAttestationPayloadV2` uses the distinct
`ota-crossing-broker/attestation-response/v2` response domain and
`ota.crossing-broker.attestation.v2\0` identity domain. It carries one signed runtime-boundary
record with a stable profile ID, content-addressed profile identity, protected-launcher attestor
identity, launcher-session binding, and an ordered closed set of observations.

This crate publishes two canonical profile definitions:

- `ota.runtime-boundary.protected-launcher/v1` requires eleven launcher and runtime-separation
  observations.
- `ota.runtime-boundary.protected-launcher-image/v1` adds bound runner-image and hardening-profile
  identities.

Every required observation must be represented with its profile-defined evidence method. The
profile also requires bounded semantic identities for launcher binary/config measurements and,
for the image profile, image/hardening-profile measurements; it forbids arbitrary identities on
the remaining observations. Core, not this wire crate, owns trust-root selection, signature
verification, refusal semantics, and archive reconciliation. Provider attestation is not part of
these profiles.

Every JSON payload is carried in one frame: a four-byte unsigned big-endian payload length followed
by at most 64 KiB of UTF-8 JSON. Signed-message and identity domains are fixed protocol constants;
this crate canonicalizes bytes and publishes profile identities but does not select trust roots.

## Production launcher foundations

The planned `systemd_protected_launcher/v1` adapter keeps broker semantics unchanged. This crate
publishes only the immutable records that Core and the launcher must agree on before that adapter
can execute:

- `LauncherPrincipalMappingV1` binds one protected job-peer identity to one distinct execution
  identity plus the fixed job-principal profile and launcher-session binding. Its identity is used
  as the existing broker `runner_principal`, so authorization covers the complete mapping rather
  than one caller label. The outer instance evidence separately binds the launcher profile.
- `OtaProcessPostureV1` is an adapter-local pre-authority record for measured
  `no_new_privs`, non-dumpable, and ptracer-clear posture. A launcher must corroborate it; the
  Ota-authored record is never sufficient authority by itself.
- `SystemdProtectedLauncherInstanceEvidenceV1` carries the complete mapping, process posture, fixed
  profile identities, and bounded invocation identities needed to rederive the signed launcher
  instance during receipt-history verification.
- `ota.authority-launcher.systemd/v1` fixes the ordered service/socket hardening semantics and
  evidence sources. Its profile identity is
  `sha256:32c49f19799e065d341c900a4ce0d7756669c0c0d4e990ffe81bbcda06291930`.
- `ota.authority-job-principal.systemd/v1` fixes the ordered job-peer, execution-principal,
  privilege, process-containment, and process-inspection requirements. Its profile identity is
  `sha256:e69ef375070bbb4f5616ba46b6f29b9a987372909016d1a1dfa40a5d4daae93d`.

These definitions do not implement systemd, inspect a host, hold an attestor key, or create a
provider claim. Core and authority-launcher must pin the same immutable protocol revision and
independently verify their respective boundaries before the adapter can be enabled.

## Status

Preview foundation. Consumers should pin an immutable Git revision until a stable crate release is
published.

## License

Apache License 2.0. See [LICENSE](LICENSE).
