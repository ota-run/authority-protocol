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
