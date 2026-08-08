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

Every JSON payload is carried in one frame: a four-byte unsigned big-endian payload length followed
by at most 64 KiB of UTF-8 JSON. Signed-message and identity domains are fixed protocol constants;
this crate canonicalizes bytes but does not select trust roots.

## Status

Preview foundation. Consumers should pin an immutable Git revision until a stable crate release is
published.

## License

Apache License 2.0. See [LICENSE](LICENSE).
