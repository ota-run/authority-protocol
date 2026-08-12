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

# Changelog

## Unreleased

- Add the protected systemd selected-execution completion and finalization protocol. Core reports
  one identity-bound terminal crossing transaction and receipt outcome; the launcher persists that
  exact completion before acknowledging it, then emits finalization only after the exact child is
  reaped and the recorded scope, cgroup, and active slot are absent. Completion and cleanup remain
  separate identities, and interrupted execution carries a concrete process exit posture.

- Add the execution-disabled authorization-decision relay envelope. Core acknowledges one exact
  verified signed decision through `authorization_decision_admission`; the launcher binds that
  acknowledgement and signed decision in `AuthorizationDecisionRelayEvidenceV1`. Add the distinct
  `authorization_decision_verified_before_lease_boundary_removed` terminal stage. These records
  establish protected relay and cleanup only; they are neither a lease nor execution authority.

- Add `ota.authority-launcher.systemd/v3` with bounded `CAP_SYS_PTRACE` so the root launcher
  can re-observe protected job and stopped-child process truth while `ProtectProc=invisible`
  remains enforced, plus ambient `CAP_SETUID` solely for its verified non-root target-principal
  transition. Bind effective systemd runtime configuration as read-only launcher state.
  Add the paired `ota.authority-job-principal.systemd/v2` profile, which permits only the mapped
  primary GID when systemd represents it in the kernel supplementary-group vector. Existing
  profile identities and archive meanings remain unchanged.

- Add `ota.authority-launcher.systemd/v2` for the separated protected-attestation producer
  boundary. It preserves V1 verification while removing launcher-owned signing credentials and
  binding the producer socket metadata and public verifier set instead.

- Add the canonical V3 protected-attestation producer protocol: domain-separated launcher claims,
  identity-bound signing request and response envelopes, exact signed-payload projection, and
  conformance vectors. The producer binding includes public verifier material and identity, key
  validity, and producer/verifier freshness maxima while carrying no private credential. These
  records define producer reconciliation only; they do not implement a signing service, broker
  decision, lease, execution, receipt, or provider attestation.

- Require V3 claims, signing requests, and signed attestations to carry instance schema 3 with the
  exact V3 launcher and V2 job-principal profiles. Legacy instance validation remains available for
  its original evidence branch and cannot be reinterpreted through a V3 identity.

- Add the identity-bound systemd launcher startup continuation that unlocks Core CLI parsing after
  exact process-posture admission without representing crossing authority. Bind the exact
  invocation, child, working-directory, posture, and principal truth. Add the distinct
  `attestation_admitted_before_authorization_boundary_removed` terminal stage so consumers cannot
  confuse posture-only cleanup with signed V3 admission and pre-authorization cleanup. Authority
  decisions use `authority_refused_boundary_removed`; malformed or substituted bridge traffic uses
  `pre_authorization_protocol_refused_boundary_removed` instead.

- Publish the v1 crossing-authority wire model, bounded framing, canonical identity helpers, and
  conformance tests.
- Add fresh-attestation-bound consumption-status query and response messages for fail-closed
  recovery after an uncertain lease-consume acknowledgement.
- Add the distinct runtime-boundary attestation v2 wire model, protected-launcher profile
  definitions, content-addressed profile identities, and downgrade-resistant conformance vectors
  without changing the v1 launcher-attestation shape.
- Add the planned production systemd protected-launcher foundation: content-addressed one-to-one
  principal mapping, adapter-local Ota process posture, archive-rederivable instance evidence, and
  closed launcher/job-principal profile definitions with requirement-specific evidence methods.
  This adds no executable launcher or provider-attested claim.
- Add an additive systemd protected-launcher instance v2 record that binds the V1 identity
  foundation to every ordered verified launcher and job-principal profile observation.
- Add a distinct systemd protected-launcher attestation v3 envelope and identity domain. It carries
  only a complete instance v2 record and leaves v1/v2 attestation compatibility unchanged.
- Add canonical identities for the untrusted launcher invocation request, the exact retained
  working-directory device/inode, and the stopped fixed-binary child process. These records are
  execution-boundary foundations only; they do not authorize or resume a child.
- Add the canonical transient systemd scope identity binding the exact stopped child, request,
  unit object, fixed slice, kernel control group, and non-delegated cleanup controls. The record is
  evidence only and cannot create, authorize, or resume a scope or child.
