//                █████
//               ░░███
//       ██████  ███████    ██████
//      ███░░███░░░███░    ░░░░░███
//     ░███ ░███  ░███      ███████
//     ░███ ░███  ░███ ███ ███░░███
//     ░░██████   ░░█████ ░░████████
//      ░░░░░░     ░░░░░   ░░░░░░░░
//
//   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.
//
//   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
//
//   Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
//   You may not use this file except in compliance with the License.
//   Unless required by applicable law or agreed to in writing, software distributed under the
//   License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//   either express or implied. See the License for the specific language governing permissions
//   and limitations under the License.
//
//   If you need additional information or have any questions, please email: os@ota.run

//! Canonical wire types and framing for Ota crossing authority.
//!
//! This crate deliberately contains no authority-selection, trust-root, approval, persistence,
//! execution, receipt, or archive policy.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION_V1: &str = "ota-crossing-broker/v1";
pub const RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2: &str = "ota-runtime-boundary-attestation/v2";
pub const SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3: &str =
    "ota-systemd-protected-launcher-attestation/v3";
pub const RUNTIME_BOUNDARY_SCHEMA_VERSION_V1: u32 = 1;
pub const PROTECTED_LAUNCHER_PROFILE_ID_V1: &str = "ota.runtime-boundary.protected-launcher/v1";
pub const PROTECTED_LAUNCHER_IMAGE_PROFILE_ID_V1: &str =
    "ota.runtime-boundary.protected-launcher-image/v1";
pub const SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1: &str = "systemd_protected_launcher/v1";
pub const SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1: &str = "ota-authority-launcher/systemd/v1";
pub const SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1: &str = "ota-authority-history/systemd/v1";
pub const SYSTEMD_LAUNCHER_PROFILE_ID_V1: &str = "ota.authority-launcher.systemd/v1";
pub const SYSTEMD_LAUNCHER_PROFILE_ID_V2: &str = "ota.authority-launcher.systemd/v2";
pub const SYSTEMD_LAUNCHER_PROFILE_ID_V3: &str = "ota.authority-launcher.systemd/v3";
pub const SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1: &str = "ota.authority-job-principal.systemd/v1";
pub const SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2: &str = "ota.authority-job-principal.systemd/v2";
pub const SYSTEMD_ATTESTOR_SOCKET_PATH_V1: &str = "/run/ota/authority-attestor.sock";
pub const SYSTEMD_PROTECTED_HISTORY_SOCKET_PATH_V1: &str = "/run/ota/authority-history.sock";
pub const SYSTEMD_ATTESTOR_SERVICE_UNIT_V1: &str = "ota-authority-attestor.service";
pub const SYSTEMD_LAUNCHER_SERVICE_UNIT_V1: &str = "ota-authority-launcher.service";
pub const OTA_PROCESS_POSTURE: &str = "ota_process_posture";
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_LAUNCHER_ARGUMENTS_V1: usize = 128;
pub const MAX_LAUNCHER_ARGUMENT_BYTES_V1: usize = 4096;
pub const MAX_LAUNCHER_AUTHORITY_ID_BYTES_V1: usize = 128;
pub const MAX_LAUNCHER_INVOCATION_ID_BYTES_V1: usize = 128;
pub const MAX_LAUNCHER_REPOSITORY_PATH_BYTES_V1: usize = 4096;
// JSON byte-array encoding can use up to four bytes per payload byte plus framing metadata.
pub const MAX_LAUNCHER_OUTPUT_PAYLOAD_BYTES_V1: usize = 15 * 1024;
pub const MAX_HISTORY_ENTRY_COUNT_V1: usize = 256;
pub const MAX_HISTORY_CHUNK_PAYLOAD_BYTES_V1: usize = 15 * 1024;
pub const MAX_HISTORY_RESPONSE_BYTES_V1: u64 = 16 * 1024 * 1024;
pub const MAX_PROTECTED_LAUNCHER_STORE_BYTES_V1: usize = 64 * 1024;

pub const CHALLENGE_REQUEST: &str = "challenge_request";
pub const ATTESTATION_RESPONSE: &str = "attestation_response";
pub const AUTHORIZATION_REQUEST: &str = "authorization_request";
pub const AUTHORIZATION_DECISION: &str = "authorization_decision";
pub const AUTHORIZATION_DECISION_ADMISSION: &str = "authorization_decision_admission";
pub const LEASE_CONSUMPTION_ADMISSION: &str = "lease_consumption_admission";
pub const LEASE_CONSUMPTION_INTENT_PERSISTENCE: &str = "lease_consumption_intent_persistence";
pub const LEASE_CONSUMPTION_PERSISTENCE: &str = "lease_consumption_persistence";
pub const LEASE_ISSUANCE: &str = "lease_issuance";
pub const LEASE_CONSUME: &str = "lease_consume";
pub const LEASE_CONSUME_RESPONSE: &str = "lease_consume_response";
pub const LEASE_CONSUMPTION_QUERY: &str = "lease_consumption_query";
pub const LEASE_CONSUMPTION_STATUS: &str = "lease_consumption_status";
pub const LAUNCHER_INVOCATION_REQUEST: &str = "launcher_invocation_request";
pub const PROTECTED_LAUNCHER_CAPABILITY: &str = "protected_launcher_capability";
pub const RUNNER_ADMINISTRATOR_AUTHORITY: &str = "runner_administrator_authority";
pub const PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT: &str =
    "protected_launcher_implementation_subject";
pub const PROTECTED_LAUNCHER_AUTHORITY_CONTEXT: &str = "protected_launcher_authority_context";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE: &str =
    "protected_launcher_capability_observation_challenge";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION: &str =
    "protected_launcher_capability_observation";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST: &str =
    "protected_launcher_capability_observation_request";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROBE_REQUEST: &str =
    "protected_launcher_capability_observation_probe_request";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_RESPONSE: &str =
    "protected_launcher_capability_observation_response";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_REQUEST: &str =
    "protected_launcher_capability_observation_signing_request";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_RESPONSE: &str =
    "protected_launcher_capability_observation_signing_response";
pub const PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER: &str =
    "protected_launcher_capability_projection_verifier";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_KEY_USAGE_V1: &str =
    "protected_launcher_capability_observation_projection";
pub const LAUNCHER_STARTUP_CONTINUATION: &str = "launcher_startup_continuation";
pub const LAUNCHER_ATTESTATION_SIGNING_REQUEST: &str = "launcher_attestation_signing_request";
pub const LAUNCHER_ATTESTATION_SIGNING_RESPONSE: &str = "launcher_attestation_signing_response";
pub const LAUNCHER_FINALIZATION_SIGNING_REQUEST: &str = "launcher_finalization_signing_request";
pub const LAUNCHER_FINALIZATION_SIGNING_RESPONSE: &str = "launcher_finalization_signing_response";
pub const LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_REQUEST: &str =
    "launcher_finalization_archive_signing_request";
pub const LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_RESPONSE: &str =
    "launcher_finalization_archive_signing_response";
pub const LAUNCHER_FINALIZATION_ARCHIVE_REQUEST: &str = "launcher_finalization_archive_request";
pub const LAUNCHER_FINALIZATION_RECOVERY_REQUEST: &str = "launcher_finalization_recovery_request";
pub const LAUNCHER_FINALIZATION_ARCHIVE_RESPONSE: &str = "launcher_finalization_archive_response";
pub const LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE: &str =
    "launcher_finalization_archive_persistence";
pub const LAUNCHER_OUTPUT: &str = "launcher_output";
pub const LAUNCHER_TERMINAL: &str = "launcher_terminal";
pub const LAUNCHER_TERMINAL_PERSISTENCE: &str = "launcher_terminal_persistence";
pub const LAUNCHER_EXECUTION_COMPLETION: &str = "launcher_execution_completion";
pub const LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE: &str =
    "launcher_execution_completion_persistence";
pub const LAUNCHER_SIGNED_EXECUTION_FINALIZATION: &str = "launcher_signed_execution_finalization";
pub const LAUNCHER_HISTORY_QUERY: &str = "launcher_history_query";
pub const LAUNCHER_HISTORY_MANIFEST: &str = "launcher_history_manifest";
pub const LAUNCHER_HISTORY_ENTRY: &str = "launcher_history_entry";
pub const LAUNCHER_HISTORY_OBJECT: &str = "launcher_history_object";
pub const LAUNCHER_HISTORY_CHUNK: &str = "launcher_history_chunk";
pub const LAUNCHER_HISTORY_PRE_QUERY_REFUSAL: &str = "launcher_history_pre_query_refusal";
pub const LAUNCHER_HISTORY_QUERY_REFUSAL: &str = "launcher_history_query_refusal";
pub const LAUNCHER_HISTORY_MANIFEST_TERMINAL: &str = "launcher_history_manifest_terminal";

pub const CHALLENGE_IDENTITY_DOMAIN_V1: &[u8] = b"ota.crossing-broker.challenge.v1\0";
pub const WORK_UNIT_IDENTITY_DOMAIN_V1: &[u8] = b"ota.crossing-broker.work-unit.v1\0";
pub const BROKER_BINDING_IDENTITY_DOMAIN_V1: &[u8] = b"ota.crossing-broker.binding.v1\0";
pub const BROKER_BINDING_IDENTITY_DOMAIN_V2: &[u8] = b"ota.crossing-broker.binding.v2\0";
pub const ATTESTATION_IDENTITY_DOMAIN_V2: &[u8] = b"ota.crossing-broker.attestation.v2\0";
pub const ATTESTATION_IDENTITY_DOMAIN_V3: &[u8] = b"ota.crossing-broker.attestation.v3\0";
pub const RUNTIME_BOUNDARY_PROFILE_IDENTITY_DOMAIN_V1: &[u8] = b"ota.runtime-boundary.profile.v1\0";
pub const LAUNCHER_PRINCIPAL_MAPPING_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.launcher.principal-mapping.v1\0";
pub const OTA_PROCESS_POSTURE_IDENTITY_DOMAIN_V1: &[u8] = b"ota.launcher.process-posture.v1\0";
pub const SYSTEMD_LAUNCHER_PROFILE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.systemd-profile.v1\0";
pub const SYSTEMD_JOB_PRINCIPAL_PROFILE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.job-principal-profile.v1\0";
pub const SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.instance.v1\0";
pub const SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V2: &[u8] =
    b"ota.authority-launcher.instance.v2\0";
pub const SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V3: &[u8] =
    b"ota.authority-launcher.instance.v3\0";
pub const SYSTEMD_LAUNCHER_SERVICE_CONFIGURATION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.systemd-service-configuration.v1\0";
pub const LAUNCHER_INVOCATION_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.invocation-request.v1\0";
pub const LAUNCHER_WORKING_DIRECTORY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.working-directory.v1\0";
pub const LAUNCHER_CHILD_PROCESS_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.child-process.v1\0";
pub const LAUNCHER_SYSTEMD_SCOPE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.systemd-scope.v1\0";
pub const PROTECTED_LAUNCHER_DESCRIPTOR_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.protected-descriptor.v1\0";
pub const PROTECTED_LAUNCHER_STORE_CONTENT_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.protected-store-content.v1\0";
pub const PROTECTED_LAUNCHER_CGROUP_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.protected-cgroup.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.protected-capability.v1\0";
pub const RUNNER_ADMINISTRATOR_AUTHORITY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.runner-administrator-authority.v1\0";
pub const PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.implementation-subject.v1\0";
pub const PROTECTED_LAUNCHER_AUTHORITY_CONTEXT_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.authority-context.v1\0";
pub const PROTECTED_LAUNCHER_INVOCATION_NONCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.invocation-nonce.v1\0";
pub const PROTECTED_LAUNCHER_BOOT_IDENTITY_DOMAIN_V1: &[u8] = b"ota.authority-launcher.boot.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_NONCE_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-observation-nonce.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-observation-challenge.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-observation-projection.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-observation-request.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROBE_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-observation-probe-request.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-observation-signing-request.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-observation-signature.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-projection-verifier.v1\0";
pub const PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_KEY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-launcher-capability-projection-key.v1\0";
pub const LAUNCHER_STARTUP_CONTINUATION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.startup-continuation.v1\0";
pub const AUTHORIZATION_DECISION_ADMISSION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.authorization-decision-admission.v1\0";
pub const AUTHORIZATION_DECISION_RELAY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.authorization-decision-relay.v1\0";
pub const LEASE_CONSUMPTION_ADMISSION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.lease-consumption-admission.v1\0";
pub const LEASE_CONSUMPTION_INTENT_RELAY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.lease-consumption-intent-relay.v1\0";
pub const LEASE_CONSUMPTION_INTENT_PERSISTENCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.lease-consumption-intent-persistence.v1\0";
pub const LEASE_CONSUMPTION_PERSISTENCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.lease-consumption-persistence.v1\0";
pub const LEASE_CONSUMPTION_RELAY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.lease-consumption-relay.v1\0";
pub const LAUNCHER_EXECUTION_COMPLETION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.execution-completion.v1\0";
pub const LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.execution-completion-persistence.v1\0";
pub const LAUNCHER_EXECUTION_FINALIZATION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.execution-finalization.v1\0";
pub const SIGNED_LAUNCHER_EXECUTION_FINALIZATION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.signed-execution-finalization.v1\0";
pub const LAUNCHER_FINALIZATION_ARCHIVE_SIDECAR_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-archive-sidecar.v1\0";
pub const LAUNCHER_FINALIZATION_RECOVERY_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-recovery-request.v1\0";
pub const LAUNCHER_FINALIZATION_SIGNING_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-signing-request.v1\0";
pub const LAUNCHER_FINALIZATION_SIGNING_RESPONSE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-signing-response.v1\0";
pub const SIGNED_LAUNCHER_FINALIZATION_ARCHIVE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.signed-finalization-archive.v1\0";
pub const LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-archive-signing-request.v1\0";
pub const LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_RESPONSE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-archive-signing-response.v1\0";
pub const LAUNCHER_FINALIZATION_ARCHIVE_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-archive-request.v1\0";
pub const LAUNCHER_FINALIZATION_ARCHIVE_RESPONSE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-archive-response.v1\0";
pub const LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-archive-persistence.v1\0";
pub const LAUNCHER_TERMINAL_FRAME_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.terminal-frame.v1\0";
pub const LAUNCHER_TERMINAL_PERSISTENCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.terminal-persistence.v1\0";
pub const LAUNCHER_EXECUTION_FINALIZATION_SIGNATURE_DOMAIN_V1: &str =
    "ota-authority-launcher/execution-finalization/v1";
pub const LAUNCHER_FINALIZATION_ARCHIVE_SIGNATURE_DOMAIN_V1: &str =
    "ota-authority-launcher/finalization-archive/v1";
pub const LAUNCHER_ATTESTATION_CLAIMS_IDENTITY_DOMAIN_V3: &[u8] =
    b"ota.authority-launcher.attestation-claims.v3\0";
pub const LAUNCHER_ATTESTATION_SIGNING_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.attestation-signing-request.v1\0";
pub const LAUNCHER_ATTESTATION_SIGNING_RESPONSE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.attestation-signing-response.v1\0";
pub const LAUNCHER_ATTESTATION_PRODUCER_BINDING_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.attestation-producer-binding.v1\0";
pub const LAUNCHER_HISTORY_QUERY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-query.v1\0";
pub const LAUNCHER_HISTORY_MANIFEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-manifest.v1\0";
pub const LAUNCHER_HISTORY_ENTRY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-entry.v1\0";
pub const LAUNCHER_HISTORY_OBJECT_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-object.v1\0";
pub const LAUNCHER_HISTORY_CHUNK_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-chunk.v1\0";
pub const LAUNCHER_HISTORY_PRE_QUERY_REFUSAL_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-pre-query-refusal.v1\0";
pub const LAUNCHER_HISTORY_QUERY_REFUSAL_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-query-refusal.v1\0";
pub const LAUNCHER_HISTORY_MANIFEST_TERMINAL_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-manifest-terminal.v1\0";
pub const CHALLENGE_REQUEST_DOMAIN_V1: &str = "ota-crossing-broker/challenge-request/v1";
pub const ATTESTATION_RESPONSE_DOMAIN_V1: &str = "ota-crossing-broker/attestation-response/v1";
pub const ATTESTATION_RESPONSE_DOMAIN_V2: &str = "ota-crossing-broker/attestation-response/v2";
pub const ATTESTATION_RESPONSE_DOMAIN_V3: &str = "ota-crossing-broker/attestation-response/v3";
pub const AUTHORIZATION_REQUEST_DOMAIN_V1: &str = "ota-crossing-broker/authorization-request/v1";
pub const AUTHORIZATION_DECISION_DOMAIN_V1: &str = "ota-crossing-broker/authorization-decision/v1";
pub const LEASE_ISSUANCE_DOMAIN_V1: &str = "ota-crossing-broker/lease-issuance/v1";
pub const LEASE_CONSUME_DOMAIN_V1: &str = "ota-crossing-broker/lease-consume/v1";
pub const LEASE_CONSUME_RESPONSE_DOMAIN_V1: &str = "ota-crossing-broker/lease-consume-response/v1";
pub const LEASE_CONSUMPTION_QUERY_DOMAIN_V1: &str =
    "ota-crossing-broker/lease-consumption-query/v1";
pub const LEASE_CONSUMPTION_STATUS_DOMAIN_V1: &str =
    "ota-crossing-broker/lease-consumption-status/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerChallenge {
    pub message_kind: String,
    pub protocol_version: String,
    pub binding_identity: String,
    pub nonce_commitment: String,
    pub work_unit_identity: String,
    pub semantic_scope_identity: String,
    pub contract_identity: String,
}

/// An untrusted request sent to the fixed systemd launcher socket.
///
/// This record is deliberately not an authority grant, semantic scope, or caller identity. The
/// service derives peer identity from the connected Unix socket, applies its protected mapping,
/// and mints the authoritative invocation identity after validating this bounded proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherInvocationRequestV1 {
    pub message_kind: String,
    pub protocol_version: String,
    pub authority_id: String,
    pub ota_arguments: Vec<String>,
    pub repository_path: String,
}

/// The exact repository directory retained by the protected launcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherWorkingDirectoryV1 {
    pub schema_version: u32,
    pub identity: String,
    pub logical_path: String,
    pub device: u64,
    pub inode: u64,
}

/// The stopped Ota child prepared by the protected launcher before systemd scope admission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherChildProcessV1 {
    pub schema_version: u32,
    pub identity: String,
    pub invocation_id: String,
    pub request_identity: String,
    pub pid: u32,
    pub process_start_time_identity: String,
    pub ota_binary_identity: String,
    pub principal_mapping_identity: String,
    pub working_directory_identity: String,
}

/// Launcher-local permission for the exact postured Ota child to continue into CLI admission.
///
/// This is not crossing authority. It unlocks command parsing so Core can freeze semantic scope
/// and create its broker challenge on the same private launcher session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherStartupContinuationV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub invocation_id: String,
    pub child_process_identity: String,
    pub working_directory_identity: String,
    pub process_posture_identity: String,
    pub principal_mapping_identity: String,
}

/// The exact non-delegated transient systemd scope containing one stopped Ota child.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherSystemdScopeV1 {
    pub schema_version: u32,
    pub identity: String,
    pub invocation_id: String,
    pub request_identity: String,
    pub child_identity: String,
    pub child_pid: u32,
    pub unit_name: String,
    pub unit_object_path: String,
    pub slice: String,
    pub control_group: String,
    pub delegate: bool,
    pub kill_mode: String,
    pub collect_mode: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedLauncherDescriptorRoleV1 {
    LauncherSessionSocket,
    VerifierStore,
    BindingStore,
    InvocationCgroup,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedLauncherDescriptorKindV1 {
    UnixStreamSocket,
    RegularFile,
    Directory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedLauncherDescriptorAccessV1 {
    ReadOnly,
    ReadWrite,
}

/// Metadata for one descriptor retained across the protected launcher boundary.
///
/// This record carries no path or file content. The launcher and Core independently reconcile
/// the live descriptor and exact bytes where the role requires them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherDescriptorV1 {
    pub schema_version: u32,
    pub identity: String,
    pub role: ProtectedLauncherDescriptorRoleV1,
    pub kind: ProtectedLauncherDescriptorKindV1,
    pub access: ProtectedLauncherDescriptorAccessV1,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: u32,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_identity: Option<String>,
}

/// Protected-launcher facts retained for one exact unprivileged Ota invocation.
///
/// This is capability evidence, not crossing authority, provider authority, or a bearer-token
/// carrier. Token and provider response bytes must never enter this record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub protocol_version: String,
    pub launcher_request_identity: String,
    pub launcher_executable_identity: String,
    pub launcher_configuration_identity: String,
    pub launcher_service_binding_identity: String,
    pub launcher_profile_identity: String,
    pub runner_administrator_identity: String,
    pub service_uid: u32,
    pub service_gid: u32,
    pub invocation_nonce_identity: String,
    pub boot_identity: String,
    pub protected_launcher_instance_identity: String,
    pub systemd_invocation_identity: String,
    pub systemd_scope_identity: String,
    pub cgroup_identity: String,
    pub child_process_identity: String,
    pub principal_mapping_identity: String,
    pub process_posture_identity: String,
    pub implementation_subject_identity: String,
    pub descriptors: Vec<ProtectedLauncherDescriptorV1>,
}

/// Stable identity of the independently administered protected-runner authority.
///
/// Installation and ownership evidence establish who controls this record. This record only
/// defines its canonical semantic identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerAdministratorAuthorityV1 {
    pub schema_version: u32,
    pub record_kind: String,
    pub identity: String,
    pub authority_id: String,
    pub authority_instance_id: String,
    pub administration_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherImplementationTargetV1 {
    pub environment: String,
    pub os: String,
    pub architecture: String,
    pub execution_mode: String,
    pub launcher_class: String,
}

/// Exact installed Launcher and Ota implementation subject for the first protected-runner target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherImplementationSubjectV1 {
    pub schema_version: u32,
    pub record_kind: String,
    pub identity: String,
    pub launcher_source_repository: String,
    pub launcher_source_revision: String,
    pub core_source_repository: String,
    pub core_source_revision: String,
    pub protocol_source_repository: String,
    pub protocol_source_revision: String,
    pub launcher_build_identity: String,
    pub core_build_identity: String,
    pub launcher_artifact_identity: String,
    pub ota_artifact_identity: String,
    pub protocol_version: String,
    pub minimum_core_version: String,
    pub maximum_exclusive_core_version: String,
    pub launcher_profile_identity: String,
    pub target: ProtectedLauncherImplementationTargetV1,
}

/// Administrator-installed static context required before live capability derivation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherAuthorityContextV1 {
    pub schema_version: u32,
    pub record_kind: String,
    pub identity: String,
    pub runner_administrator: RunnerAdministratorAuthorityV1,
    pub implementation_subject: ProtectedLauncherImplementationSubjectV1,
}

/// Independently observed records used to reconcile a protected capability.
///
/// This is an in-process verification input, not a serialized wire message. The protected store
/// bytes are consumed only to rederive their role-specific identities.
#[derive(Clone, Copy)]
pub struct ProtectedLauncherCapabilityEvidenceV1<'a> {
    pub request: &'a LauncherInvocationRequestV1,
    pub child: &'a LauncherChildProcessV1,
    pub scope: &'a LauncherSystemdScopeV1,
    pub principal_mapping: &'a LauncherPrincipalMappingV1,
    pub process_posture: &'a OtaProcessPostureV1,
    pub launcher_instance: &'a SystemdProtectedLauncherInstanceEvidenceV2,
    pub launcher_executable_identity: &'a str,
    pub launcher_configuration_identity: &'a str,
    pub launcher_service_binding_identity: &'a str,
    pub launcher_profile_identity: &'a str,
    pub runner_administrator_identity: &'a str,
    pub service_uid: u32,
    pub service_gid: u32,
    pub invocation_nonce_identity: &'a str,
    pub boot_identity: &'a str,
    pub implementation_subject_identity: &'a str,
    pub observed_descriptors: &'a [ProtectedLauncherDescriptorV1],
    pub verifier_store_bytes: &'a [u8],
    pub binding_store_bytes: &'a [u8],
}

/// One fresh Core-owned public challenge for a protected capability observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationChallengeV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub identity: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: String,
    pub workflow_reference: String,
    pub nonce_commitment: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationTargetV1 {
    pub environment: String,
    pub os: String,
    pub architecture: String,
}

/// Exact unsigned public payload derived by the root-owned launcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationProjectionPayloadV1 {
    pub schema_version: u32,
    pub evidence_kind: String,
    pub challenge_identity: String,
    pub derivation: String,
    pub target: ProtectedLauncherCapabilityObservationTargetV1,
    pub capability_class: String,
    pub runner_version: String,
    pub signing_key_identity: String,
}

/// Public signed envelope. The protected capability identity never enters this record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationProjectionV1 {
    pub payload: ProtectedLauncherCapabilityObservationProjectionPayloadV1,
    pub projection_identity: String,
    pub signature: String,
}

/// Fixed local request carrying Core's fresh challenge to the protected launcher.
///
/// `nonce` is confidential local transport input. It is never a public projection field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub identity: String,
    pub challenge: ProtectedLauncherCapabilityObservationChallengeV1,
    pub nonce: String,
    pub runner_version: String,
    /// Protected identity of the exact Launcher invocation Core expects to observe.
    /// This remains local transport input and is never projected publicly.
    pub expected_launcher_request_identity: String,
}

/// One closed local request that binds an accepted Launcher invocation to Core's fresh
/// capability-observation request. Neither record is public projection material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationProbeRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub identity: String,
    pub invocation: LauncherInvocationRequestV1,
    pub observation: ProtectedLauncherCapabilityObservationRequestV1,
}

/// Fixed local response carrying only the bounded public projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationResponseV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub projection: ProtectedLauncherCapabilityObservationProjectionV1,
}

/// Protected Launcher-to-Attestor request for one exact capability-observation signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationSigningRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub identity: String,
    pub producer_binding_identity: String,
    pub verifier_identity: String,
    pub protected_capability_identity: String,
    pub payload: ProtectedLauncherCapabilityObservationProjectionPayloadV1,
    pub projection_identity: String,
}

/// Protected Attestor response containing only the signed public projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityObservationSigningResponseV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub projection: ProtectedLauncherCapabilityObservationProjectionV1,
}

/// Administrator-installed public verifier for exactly one projection protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedLauncherCapabilityProjectionVerifierV1 {
    pub schema_version: u32,
    pub record_kind: String,
    pub identity: String,
    pub public_key: String,
    pub key_identity: String,
    pub key_usage: String,
    pub signature_domain: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherOutputStreamV1 {
    Stdout,
    Stderr,
}

/// A service-to-client output frame. Payload bytes are encoded by Serde as a JSON byte array so
/// the framing contract remains binary-safe without making a text-output claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherOutputFrameV1 {
    pub message_kind: String,
    pub protocol_version: String,
    pub invocation_id: String,
    pub sequence: u64,
    pub stream: LauncherOutputStreamV1,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherTerminalOutcomeV1 {
    Completed,
    Refused,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherTerminalStageV1 {
    RequestRefusedBeforeBoundary,
    PostureAdmittedBoundaryRemoved,
    AuthorityRefusedBoundaryRemoved,
    PreAuthorizationProtocolRefusedBoundaryRemoved,
    AttestationAdmittedBeforeAuthorizationBoundaryRemoved,
    AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved,
    LeaseConsumedBeforeExecutionDisabledBoundaryRemoved,
    SelectedExecutionCompletedBoundaryRemoved,
    SelectedExecutionFailedBoundaryRemoved,
    SelectedExecutionInterruptedBoundaryRemoved,
    BoundaryFailed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherExecutionOutcomeV1 {
    Completed,
    Failed,
    Interrupted,
}

/// How the launcher established the child-exit portion of terminal cleanup evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherChildExitPostureV1 {
    LauncherObservedAndReaped,
    RecoveredAbsentCompletionBound,
}

/// Core-authored selected-work result. This is persisted before the protected child exits, but it
/// is not launcher cleanup evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherExecutionCompletionV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub invocation_id: String,
    pub lease_consumption_admission_identity: String,
    pub work_unit_identity: String,
    pub crossing_transaction_id: String,
    pub pending_crossing_transaction_identity: String,
    pub crossing_transaction_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_archive_identity: Option<String>,
    pub outcome: LauncherExecutionOutcomeV1,
    pub exit_code: Option<i32>,
    pub receipt_status: String,
}

/// Launcher acknowledgement that the exact Core completion is durable in the active-slot journal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherExecutionCompletionPersistenceV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub completion_identity: String,
}

/// Launcher-authored evidence emitted only after the exact child and systemd boundary are absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherExecutionFinalizationV1 {
    pub schema_version: u32,
    pub identity: String,
    pub completion: LauncherExecutionCompletionV1,
    pub child_identity: String,
    pub scope_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_exit_posture: Option<LauncherChildExitPostureV1>,
    pub observed_exit_code: Option<i32>,
    pub child_reaped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_absent: Option<bool>,
    pub scope_removed: bool,
    pub cgroup_empty_or_absent: bool,
    pub active_slot_removed: bool,
}

/// Portable producer-signed form of launcher cleanup evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLauncherExecutionFinalizationV1 {
    pub schema_version: u32,
    pub identity: String,
    pub finalization: LauncherExecutionFinalizationV1,
    pub producer_binding_identity: String,
    pub issued_at: String,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

/// Producer-signed binding between exact cleanup evidence and one immutable Ota receipt archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLauncherFinalizationArchiveV1 {
    pub schema_version: u32,
    pub identity: String,
    pub signed_finalization_identity: String,
    pub receipt_archive_identity: String,
    pub crossing_transaction_identity: String,
    pub producer_binding_identity: String,
    pub issued_at: String,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

/// Detached producer-authenticated carrier attached beside an immutable Ota receipt archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationArchiveSidecarV1 {
    pub schema_version: u32,
    pub identity: String,
    pub signed_finalization: SignedLauncherExecutionFinalizationV1,
    pub signed_archive: SignedLauncherFinalizationArchiveV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherSignedExecutionFinalizationFrameV1 {
    pub message_kind: String,
    pub protocol_version: String,
    pub invocation_id: String,
    pub signed_finalization: SignedLauncherExecutionFinalizationV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationSigningRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub finalization: LauncherExecutionFinalizationV1,
    pub producer_binding_identity: String,
    pub launcher_service_binding_identity: String,
    pub launcher_configuration_identity: String,
    pub launcher_executable_identity: String,
    pub launcher_profile_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationSigningResponseV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub signed_finalization: SignedLauncherExecutionFinalizationV1,
    pub response_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationArchiveSigningRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub signed_finalization: SignedLauncherExecutionFinalizationV1,
    pub receipt_archive_identity: String,
    pub crossing_transaction_identity: String,
    pub producer_binding_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationArchiveSigningResponseV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub signed_archive: SignedLauncherFinalizationArchiveV1,
    pub response_identity: String,
}

/// Client request to bind one exact receipt archive to retained launcher cleanup evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationArchiveRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub authority_id: String,
    pub launcher_request_identity: String,
    pub receipt_archive_identity: String,
    pub crossing_transaction_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_finalization_identity: Option<String>,
}

/// Reconnect request for retained finalization state before the client has the signed completion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationRecoveryRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub authority_id: String,
    pub launcher_request_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationArchiveResponseV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub response_identity: String,
    pub request_identity: String,
    pub invocation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_file_name: Option<String>,
    pub sidecar: LauncherFinalizationArchiveSidecarV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherFinalizationArchivePersistenceV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub identity: String,
    pub request_identity: String,
    pub sidecar_identity: String,
}

/// The sole terminal frame for one launcher invocation. A client must not treat any output frame
/// as an execution result before it receives this record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherTerminalFrameV1 {
    pub message_kind: String,
    pub protocol_version: String,
    pub invocation_id: String,
    pub outcome: LauncherTerminalOutcomeV1,
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<LauncherTerminalStageV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization: Option<LauncherExecutionFinalizationV1>,
}

/// A bounded protected-history query. Repository, authority, and catalog selection are derived by
/// the protected service from the connected peer and administrator-owned mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryQueryV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub query_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_identity: Option<String>,
    pub query_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryManifestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub query_identity: String,
    pub repository_binding_identity: String,
    pub catalog_namespace_identity: String,
    pub operator_profile_identity: String,
    pub operator_peer_identity: String,
    pub operator_attribution: LauncherHistoryOperatorAttributionV1,
    pub operator_posture: LauncherHistoryOperatorPostureV1,
    pub catalog_entry_identities: Vec<String>,
    pub total_selected_count: u32,
    /// Exact sum of the selected archive, contract-snapshot, and sidecar object byte lengths.
    pub bounded_response_bytes: u64,
    pub catalog_snapshot_identity: String,
    pub manifest_identity: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherHistoryOperatorAttributionV1 {
    NonAgent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherHistoryOperatorPostureV1 {
    LeastPrivilegeOperatorPeerVerified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherHistoryObjectKindV1 {
    Archive,
    ContractSnapshot,
    Sidecar,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryEntryV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub manifest_identity: String,
    pub entry_ordinal: u32,
    pub catalog_identity: String,
    pub archive_object_identity: String,
    pub contract_snapshot_object_identity: String,
    pub sidecar_object_identity: String,
    pub entry_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryObjectV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub manifest_identity: String,
    pub entry_ordinal: u32,
    pub catalog_identity: String,
    pub object_kind: LauncherHistoryObjectKindV1,
    pub content_identity: String,
    pub byte_length: u64,
    pub chunk_count: u32,
    pub object_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryChunkV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub object_identity: String,
    pub chunk_ordinal: u32,
    pub bytes: Vec<u8>,
    pub chunk_identity: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherHistoryRefusalReasonV1 {
    PeerAdmissionRefused,
    MalformedQuery,
    UnsupportedProtocol,
    RepositoryMappingMissing,
    RepositoryMappingAmbiguous,
    ResultTooLarge,
    CatalogUnavailable,
    CatalogInvalid,
    ObjectUnavailable,
    ObjectInvalid,
    ServiceUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryPreQueryRefusalV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub refusal_nonce: String,
    pub reason: LauncherHistoryRefusalReasonV1,
    pub terminal_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryQueryRefusalV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub query_identity: String,
    pub reason: LauncherHistoryRefusalReasonV1,
    pub terminal_identity: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherHistoryManifestPostureV1 {
    Complete,
    Invalid,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherHistoryManifestTerminalV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub protocol_version: String,
    pub query_identity: String,
    pub manifest_identity: String,
    pub returned_count: u32,
    pub posture: LauncherHistoryManifestPostureV1,
    pub terminal_identity: String,
}

/// Client acknowledgement that the exact terminal frame was received. Selected execution keeps
/// its protected finalization journal until this identity-bound acknowledgement is durable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherTerminalPersistenceV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub identity: String,
    pub invocation_id: String,
    pub terminal_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherAttestationPayload {
    pub message_kind: String,
    pub binding_identity: String,
    pub challenge_nonce_commitment: String,
    pub invocation_id: String,
    pub work_unit_identity: String,
    pub semantic_scope_identity: String,
    pub runner_principal: String,
    pub channel_delivery: String,
    pub authenticated_origin: String,
    pub authority_mounts: Vec<String>,
    pub issuer: String,
    pub audience: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLauncherAttestation {
    pub payload: LauncherAttestationPayload,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBoundaryAttestorKind {
    ProtectedLauncher,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBoundaryObservationState {
    Verified,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBoundaryObservationName {
    JobPrincipalNonRoot,
    AuthorityBindingWriteDenied,
    AttestorStateWriteDenied,
    BrokerCredentialsAbsentFromJob,
    BrokerCredentialsAbsentFromTask,
    BrokerSessionNonInheritable,
    BrokerSessionNotReacquirable,
    HostControlSocketUnavailable,
    PrivilegeEscalationUnavailable,
    LauncherBinaryIdentityBound,
    LauncherConfigIdentityBound,
    RunnerImageIdentityBound,
    HardeningProfileIdentityBound,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBoundaryEvidenceMethod {
    LauncherPrincipalBinding,
    TargetPrincipalAccessCheck,
    LauncherEnvironmentExclusion,
    ChildEnvironmentExclusion,
    DescriptorCloexecVerification,
    ProtectedSessionLifetime,
    LauncherPrivilegePolicy,
    ProtectedBinaryMeasurement,
    ProtectedConfigMeasurement,
    ProtectedImageMeasurement,
    ProtectedProfileMeasurement,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBoundarySemanticIdentityPosture {
    Required,
    Forbidden,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBoundaryObservationRequirement {
    pub name: RuntimeBoundaryObservationName,
    pub evidence_method: RuntimeBoundaryEvidenceMethod,
    pub semantic_identity: RuntimeBoundarySemanticIdentityPosture,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBoundaryProfileDefinition {
    pub schema_version: u32,
    pub profile_id: String,
    pub attestor_kind: RuntimeBoundaryAttestorKind,
    pub observations: Vec<RuntimeBoundaryObservationRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBoundaryObservation {
    pub name: RuntimeBoundaryObservationName,
    pub state: RuntimeBoundaryObservationState,
    pub evidence_method: RuntimeBoundaryEvidenceMethod,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBoundaryAttestation {
    pub schema_version: u32,
    pub profile_id: String,
    pub profile_identity: String,
    pub attestor_kind: RuntimeBoundaryAttestorKind,
    pub attestor_instance_identity: String,
    pub launcher_session_binding_identity: String,
    pub observations: Vec<RuntimeBoundaryObservation>,
}

/// Additive v2 attestation payload. The v1 payload remains unchanged for archive compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherAttestationPayloadV2 {
    pub message_kind: String,
    pub attestation_protocol_version: String,
    pub binding_identity: String,
    pub challenge_nonce_commitment: String,
    pub invocation_id: String,
    pub work_unit_identity: String,
    pub semantic_scope_identity: String,
    pub runner_principal: String,
    pub channel_delivery: String,
    pub authenticated_origin: String,
    pub authority_mounts: Vec<String>,
    pub runtime_boundary: RuntimeBoundaryAttestation,
    pub issuer: String,
    pub audience: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLauncherAttestationV2 {
    pub payload: LauncherAttestationPayloadV2,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

/// Additive v3 attestation for the closed systemd protected-launcher profile.
/// The v1 and v2 shapes remain immutable for archive compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherAttestationPayloadV3 {
    pub message_kind: String,
    pub attestation_protocol_version: String,
    pub binding_identity: String,
    pub challenge_nonce_commitment: String,
    pub invocation_id: String,
    pub work_unit_identity: String,
    pub semantic_scope_identity: String,
    pub runner_principal: String,
    pub channel_delivery: String,
    pub authenticated_origin: String,
    pub authority_mounts: Vec<String>,
    pub systemd_protected_launcher: SystemdProtectedLauncherInstanceEvidenceV2,
    pub issuer: String,
    pub audience: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLauncherAttestationV3 {
    pub payload: LauncherAttestationPayloadV3,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

/// Launcher-collected V3 claims before producer-owned freshness and signature fields exist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherAttestationClaimsV3 {
    pub message_kind: String,
    pub attestation_protocol_version: String,
    pub binding_identity: String,
    pub challenge_nonce_commitment: String,
    pub invocation_id: String,
    pub work_unit_identity: String,
    pub semantic_scope_identity: String,
    pub runner_principal: String,
    pub channel_delivery: String,
    pub authenticated_origin: String,
    pub authority_mounts: Vec<String>,
    pub systemd_protected_launcher: SystemdProtectedLauncherInstanceEvidenceV2,
    pub issuer: String,
    pub audience: String,
}

/// Exact launcher request to the separately protected V3 attestation producer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherAttestationSigningRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub challenge: BrokerChallenge,
    pub claims_identity: String,
    pub claims: LauncherAttestationClaimsV3,
    pub launcher_service_binding_identity: String,
    pub launcher_configuration_identity: String,
    pub launcher_executable_identity: String,
    pub launcher_profile_identity: String,
    pub producer_binding_identity: String,
    pub producer_audience: String,
    pub requested_maximum_validity_seconds: u64,
}

/// Producer response envelope binding the signed attestation back to one exact request and claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherAttestationSigningResponseV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub claims_identity: String,
    pub attestation: SignedLauncherAttestationV3,
    pub response_identity: String,
}

/// Administrator-owned identity of the separately protected attestation producer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherAttestationProducerBindingV1 {
    pub schema_version: u32,
    pub identity: String,
    pub producer_id: String,
    pub socket_path: String,
    pub service_unit: String,
    pub launcher_service_unit: String,
    pub launcher_service_binding_identity: String,
    pub launcher_configuration_identity: String,
    pub launcher_profile_identity: String,
    pub launcher_executable_identity: String,
    pub producer_executable_identity: String,
    pub verifier_key_set_identity: String,
    pub signing_key_id: String,
    pub signing_public_key: String,
    pub signing_public_key_identity: String,
    pub signing_key_not_before: String,
    pub signing_key_not_after: String,
    pub issuer: String,
    pub audience: String,
    pub maximum_attestation_age_seconds: u64,
    pub verifier_maximum_age_seconds: u64,
    pub maximum_request_bytes: usize,
    pub read_write_timeout_seconds: u64,
    pub issuance_state_directory: String,
    pub signing_credential_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnixPrincipalIdentity {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub filesystem_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub filesystem_gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LauncherPrincipalMappingV1 {
    pub schema_version: u32,
    pub identity: String,
    pub job_peer: UnixPrincipalIdentity,
    pub execution: UnixPrincipalIdentity,
    pub job_principal_profile_identity: String,
    pub launcher_session_binding_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OtaProcessPostureV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub pid: u32,
    pub process_start_time_identity: String,
    pub ota_binary_identity: String,
    pub no_new_privs: bool,
    pub dumpable: u32,
    pub ptracer_clear_applied: bool,
    pub principal_mapping_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdProfileSetting {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemdLauncherEvidenceSource {
    ProtectedFileIdentity,
    SystemdManagerProperty,
    SocketPeerCredentials,
    ProcProcessStatus,
    ProcDescriptorInspection,
    ProcUnixSocketInspection,
    ProtectedSocketIdentity,
    TargetPrincipalAccessProbe,
    OtaProcessPosture,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdLauncherProfileDefinitionV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub service_settings: Vec<SystemdProfileSetting>,
    pub socket_settings: Vec<SystemdProfileSetting>,
    pub invocation_scope_settings: Vec<SystemdProfileSetting>,
    pub evidence_sources: Vec<SystemdLauncherEvidenceSource>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemdJobPrincipalRequirement {
    DistinctOneToOnePrincipals,
    PeerIdentityMatchesProtectedMapping,
    PeerNoNewPrivileges,
    PeerCapabilitiesEmpty,
    PeerSupplementaryGroupsEmpty,
    PeerSupplementaryGroupsLimitedToPrimary,
    RunnerServiceIdentityBound,
    AllPrincipalProcessesContained,
    AccountsLocked,
    NonLoginShells,
    SudoPolicyDenied,
    SystemdPolicyDenied,
    PolkitPolicyDenied,
    ProtectedPathsWriteDenied,
    HostControlSocketsDenied,
    ExecutionLauncherSocketDenied,
    OtaProcessNonDumpable,
    OtaPtracerCleared,
    OtaProcessInspectionDenied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemdJobPrincipalEvidenceMethod {
    ProtectedMappingConfiguration,
    ProcPeerStatus,
    ProtectedRunnerServiceIdentity,
    ProcPrincipalCgroupEnumeration,
    AccountDatabaseInspection,
    SudoPolicyQuery,
    SystemdManagerAuthorizationQuery,
    PolkitAuthorizationQuery,
    TargetPrincipalAccessProbe,
    OtaProcessPosture,
    ProcessAccessProbe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdJobPrincipalRequirementDefinition {
    pub requirement: SystemdJobPrincipalRequirement,
    pub evidence_methods: Vec<SystemdJobPrincipalEvidenceMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdJobPrincipalProfileDefinitionV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub requirements: Vec<SystemdJobPrincipalRequirementDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdProtectedLauncherInstanceEvidenceV1 {
    pub schema_version: u32,
    pub identity: String,
    pub adapter: String,
    pub principal_mapping: LauncherPrincipalMappingV1,
    pub process_posture: OtaProcessPostureV1,
    pub systemd_launcher_profile_identity: String,
    pub systemd_job_principal_profile_identity: String,
    pub launcher_session_binding_identity: String,
    pub systemd_invocation_identity: String,
    pub working_directory_identity: String,
    pub child_process_identity: String,
}

/// Complete systemd protected-launcher evidence. Schema 2 preserves the legacy V1/V2 profile
/// branch; schema 3 exclusively carries the V3 launcher and V2 job-principal profiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdProtectedLauncherInstanceEvidenceV2 {
    pub schema_version: u32,
    pub identity: String,
    pub instance_v1: SystemdProtectedLauncherInstanceEvidenceV1,
    pub launcher_observations: Vec<SystemdLauncherObservation>,
    pub job_principal_observations: Vec<SystemdJobPrincipalObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdLauncherObservation {
    pub source: SystemdLauncherEvidenceSource,
    pub state: RuntimeBoundaryObservationState,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdJobPrincipalObservation {
    pub requirement: SystemdJobPrincipalRequirement,
    pub evidence_methods: Vec<SystemdJobPrincipalEvidenceMethod>,
    pub state: RuntimeBoundaryObservationState,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedBrokerMessage<T> {
    pub payload: T,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub message_kind: String,
    pub binding_identity: String,
    pub authority_id: String,
    pub attestation_identity: String,
    pub challenge_nonce_commitment: String,
    pub work_unit_identity: String,
    pub contract_identity: String,
    pub semantic_scope_identity: String,
    pub runner_principal: String,
    pub actor_mode: String,
    pub requested_lifetime_seconds: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allowed,
    Denied,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionPayload {
    pub message_kind: String,
    pub request_identity: String,
    pub binding_identity: String,
    pub authority_id: String,
    pub attestation_identity: String,
    pub challenge_nonce_commitment: String,
    pub work_unit_identity: String,
    pub contract_identity: String,
    pub semantic_scope_identity: String,
    pub decision: AuthorizationDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_reference: Option<String>,
    pub broker_revision: u64,
    pub issued_at: String,
    pub expires_at: String,
}

/// Core-authored acknowledgement that one signed broker decision was verified on the protected
/// launcher session. This record is channel-bound integrity evidence, not broker authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionAdmissionV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub request_identity: String,
    pub authorization_decision_identity: String,
    pub binding_identity: String,
    pub attestation_identity: String,
    pub work_unit_identity: String,
    pub contract_identity: String,
    pub semantic_scope_identity: String,
    pub decision: AuthorizationDecision,
}

/// Launcher-owned durable reconciliation of one relayed signed decision and Core's exact
/// verification acknowledgement. The signed decision remains the authority; this envelope only
/// proves what crossed the protected local session before cleanup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionRelayEvidenceV1 {
    pub schema_version: u32,
    pub identity: String,
    pub request_identity: String,
    pub authorization_decision: SignedBrokerMessage<AuthorizationDecisionPayload>,
    pub authorization_decision_identity: String,
    pub admission: AuthorizationDecisionAdmissionV1,
}

/// Core-authored acknowledgement that one broker lease consumption response was verified and
/// durably recorded in the crossing transaction. This is local channel evidence, never a broker
/// authorization decision or a selected-work permit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumptionAdmissionV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub binding_identity: String,
    pub prepared_lease_identity: String,
    pub consume_request_identity: String,
    pub consume_response_identity: String,
    pub work_unit_identity: String,
    pub crossing_transaction_id: String,
    pub crossing_transaction_identity: String,
}

/// Launcher-owned durable intent recorded before the consume request reaches the broker.
/// This is the protected carrier journal for the execution-disabled systemd path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumptionIntentRelayEvidenceV1 {
    pub schema_version: u32,
    pub identity: String,
    pub authorization_decision_relay_identity: String,
    pub prepared_lease: SignedBrokerMessage<PreparedLeasePayload>,
    pub prepared_lease_identity: String,
    pub consume_request: LeaseConsumeRequest,
    pub consume_request_identity: String,
}

/// Launcher acknowledgement that the exact consume intent is fsynced before broker forwarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumptionIntentPersistenceV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub consumption_intent_identity: String,
}

/// Launcher-authored acknowledgement that the exact consumption relay evidence is durable in
/// its active-slot journal. Core must receive this before it can finalize execution-disabled use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumptionPersistenceV1 {
    pub schema_version: u32,
    pub identity: String,
    pub message_kind: String,
    pub consumption_admission_identity: String,
}

/// Launcher-owned durable reconciliation of the exact prepared lease, consume exchange, and
/// Core persistence acknowledgement. It is bounded bridge evidence; broker signatures remain the
/// authority and selected execution is deliberately outside this record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumptionRelayEvidenceV1 {
    pub schema_version: u32,
    pub identity: String,
    pub authorization_decision_relay_identity: String,
    pub prepared_lease: SignedBrokerMessage<PreparedLeasePayload>,
    pub prepared_lease_identity: String,
    pub consume_request: LeaseConsumeRequest,
    pub consume_request_identity: String,
    pub consume_response: SignedBrokerMessage<LeaseConsumeResponsePayload>,
    pub consume_response_identity: String,
    pub admission: LeaseConsumptionAdmissionV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedLeasePayload {
    pub message_kind: String,
    pub authorization_decision_identity: String,
    pub binding_identity: String,
    pub authority_id: String,
    pub attestation_identity: String,
    pub challenge_nonce_commitment: String,
    pub work_unit_identity: String,
    pub contract_identity: String,
    pub semantic_scope_identity: String,
    pub runner_principal: String,
    pub broker_revision: u64,
    pub lease_sequence: u64,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumeRequest {
    pub message_kind: String,
    pub binding_identity: String,
    pub lease_identity: String,
    pub challenge_nonce_commitment: String,
    pub work_unit_identity: String,
    pub crossing_transaction_id: String,
    pub crossing_transaction_identity: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LeaseConsumeState {
    Consumed,
    AlreadyConsumed,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumeResponsePayload {
    pub message_kind: String,
    pub consume_request_identity: String,
    pub binding_identity: String,
    pub lease_identity: String,
    pub challenge_nonce_commitment: String,
    pub work_unit_identity: String,
    pub crossing_transaction_id: String,
    pub crossing_transaction_identity: String,
    pub state: LeaseConsumeState,
    pub broker_revision: u64,
    pub consumed_at: String,
}

/// Fresh-session query for the terminal status of one exact prior consume request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumptionQuery {
    pub message_kind: String,
    pub binding_identity: String,
    pub attestation_identity: String,
    pub recovery_challenge_nonce_commitment: String,
    pub recovery_work_unit_identity: String,
    pub lease_identity: String,
    pub consume_request_identity: String,
    pub original_work_unit_identity: String,
    pub crossing_transaction_id: String,
    pub crossing_transaction_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum LeaseConsumptionStatus {
    Consumed {
        consume_response: Box<SignedBrokerMessage<LeaseConsumeResponsePayload>>,
    },
    NotConsumed,
    Unknown,
}

/// Broker-signed recovery result for one exact prior consume request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseConsumptionStatusPayload {
    pub message_kind: String,
    pub query_identity: String,
    pub binding_identity: String,
    pub attestation_identity: String,
    pub recovery_challenge_nonce_commitment: String,
    pub recovery_work_unit_identity: String,
    pub lease_identity: String,
    pub consume_request_identity: String,
    pub original_work_unit_identity: String,
    pub crossing_transaction_id: String,
    pub crossing_transaction_identity: String,
    pub broker_revision: u64,
    pub observed_at: String,
    pub status: LeaseConsumptionStatus,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("authority protocol frame exceeds the 64 KiB limit")]
    FrameTooLarge,
    #[error("authority protocol frame is incomplete")]
    IncompleteFrame,
    #[error("authority protocol canonicalization failed")]
    Canonicalization,
    #[error("authority protocol record is semantically invalid")]
    InvalidRecord,
}

pub fn validate_launcher_invocation_request_v1(
    request: &LauncherInvocationRequestV1,
) -> Result<(), ProtocolError> {
    if request.message_kind != LAUNCHER_INVOCATION_REQUEST
        || request.protocol_version != SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1
        || !is_bounded_label(&request.authority_id, MAX_LAUNCHER_AUTHORITY_ID_BYTES_V1)
        || request.ota_arguments.is_empty()
        || request.ota_arguments.len() > MAX_LAUNCHER_ARGUMENTS_V1
        || !is_absolute_bounded_path(
            &request.repository_path,
            MAX_LAUNCHER_REPOSITORY_PATH_BYTES_V1,
        )
        || request.ota_arguments.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > MAX_LAUNCHER_ARGUMENT_BYTES_V1
                || argument.contains('\0')
        })
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn launcher_invocation_request_identity(
    request: &LauncherInvocationRequestV1,
) -> Result<String, ProtocolError> {
    validate_launcher_invocation_request_v1(request)?;
    message_identity(LAUNCHER_INVOCATION_REQUEST_IDENTITY_DOMAIN_V1, request)
}

pub fn launcher_working_directory_identity(
    directory: &LauncherWorkingDirectoryV1,
) -> Result<String, ProtocolError> {
    if directory.schema_version != 1
        || !is_absolute_bounded_path(
            directory.logical_path.as_str(),
            MAX_LAUNCHER_REPOSITORY_PATH_BYTES_V1,
        )
        || directory.inode == 0
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = directory.clone();
    canonical.identity.clear();
    message_identity(LAUNCHER_WORKING_DIRECTORY_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_child_process_identity(
    child: &LauncherChildProcessV1,
) -> Result<String, ProtocolError> {
    if child.schema_version != 1
        || !is_bounded_label(
            child.invocation_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(child.request_identity.as_str())
        || child.pid == 0
        || !is_sha256_identity(child.process_start_time_identity.as_str())
        || !is_sha256_identity(child.ota_binary_identity.as_str())
        || !is_sha256_identity(child.principal_mapping_identity.as_str())
        || !is_sha256_identity(child.working_directory_identity.as_str())
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = child.clone();
    canonical.identity.clear();
    message_identity(LAUNCHER_CHILD_PROCESS_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_startup_continuation_identity(
    continuation: &LauncherStartupContinuationV1,
) -> Result<String, ProtocolError> {
    if continuation.schema_version != 1
        || continuation.message_kind != LAUNCHER_STARTUP_CONTINUATION
        || !is_bounded_label(
            continuation.invocation_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(&continuation.child_process_identity)
        || !is_sha256_identity(&continuation.working_directory_identity)
        || !is_sha256_identity(&continuation.process_posture_identity)
        || !is_sha256_identity(&continuation.principal_mapping_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = continuation.clone();
    canonical.identity.clear();
    message_identity(LAUNCHER_STARTUP_CONTINUATION_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn authorization_decision_admission_v1_identity(
    admission: &AuthorizationDecisionAdmissionV1,
) -> Result<String, ProtocolError> {
    if admission.schema_version != 1
        || admission.message_kind != AUTHORIZATION_DECISION_ADMISSION
        || !is_sha256_identity(&admission.request_identity)
        || !is_sha256_identity(&admission.authorization_decision_identity)
        || !is_sha256_identity(&admission.binding_identity)
        || !is_sha256_identity(&admission.attestation_identity)
        || !is_sha256_identity(&admission.work_unit_identity)
        || !is_sha256_identity(&admission.contract_identity)
        || !is_sha256_identity(&admission.semantic_scope_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = admission.clone();
    canonical.identity.clear();
    message_identity(
        AUTHORIZATION_DECISION_ADMISSION_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn authorization_decision_relay_evidence_v1_identity(
    evidence: &AuthorizationDecisionRelayEvidenceV1,
) -> Result<String, ProtocolError> {
    let decision_identity = message_identity(
        AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(),
        &evidence.authorization_decision,
    )?;
    if evidence.schema_version != 1
        || !is_sha256_identity(&evidence.request_identity)
        || decision_identity != evidence.authorization_decision_identity
        || authorization_decision_admission_v1_identity(&evidence.admission)?
            != evidence.admission.identity
        || evidence.admission.request_identity != evidence.request_identity
        || evidence.authorization_decision.payload.request_identity != evidence.request_identity
        || evidence.admission.authorization_decision_identity
            != evidence.authorization_decision_identity
        || evidence.admission.binding_identity
            != evidence.authorization_decision.payload.binding_identity
        || evidence.admission.attestation_identity
            != evidence.authorization_decision.payload.attestation_identity
        || evidence.admission.work_unit_identity
            != evidence.authorization_decision.payload.work_unit_identity
        || evidence.admission.contract_identity
            != evidence.authorization_decision.payload.contract_identity
        || evidence.admission.semantic_scope_identity
            != evidence
                .authorization_decision
                .payload
                .semantic_scope_identity
        || evidence.admission.decision != evidence.authorization_decision.payload.decision
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = evidence.clone();
    canonical.identity.clear();
    message_identity(AUTHORIZATION_DECISION_RELAY_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn lease_consumption_admission_v1_identity(
    admission: &LeaseConsumptionAdmissionV1,
) -> Result<String, ProtocolError> {
    if admission.schema_version != 1
        || admission.message_kind != LEASE_CONSUMPTION_ADMISSION
        || !is_sha256_identity(&admission.binding_identity)
        || !is_sha256_identity(&admission.prepared_lease_identity)
        || !is_sha256_identity(&admission.consume_request_identity)
        || !is_sha256_identity(&admission.consume_response_identity)
        || !is_sha256_identity(&admission.work_unit_identity)
        || !is_bounded_label(
            admission.crossing_transaction_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(&admission.crossing_transaction_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = admission.clone();
    canonical.identity.clear();
    message_identity(LEASE_CONSUMPTION_ADMISSION_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn lease_consumption_intent_relay_evidence_v1_identity(
    evidence: &LeaseConsumptionIntentRelayEvidenceV1,
) -> Result<String, ProtocolError> {
    let prepared_lease_identity = message_identity(
        LEASE_ISSUANCE_DOMAIN_V1.as_bytes(),
        &evidence.prepared_lease,
    )?;
    let consume_request_identity = message_identity(
        LEASE_CONSUME_DOMAIN_V1.as_bytes(),
        &evidence.consume_request,
    )?;
    if evidence.schema_version != 1
        || !is_sha256_identity(&evidence.authorization_decision_relay_identity)
        || prepared_lease_identity != evidence.prepared_lease_identity
        || consume_request_identity != evidence.consume_request_identity
        || evidence.consume_request.lease_identity != evidence.prepared_lease_identity
        || evidence.consume_request.binding_identity
            != evidence.prepared_lease.payload.binding_identity
        || evidence.consume_request.work_unit_identity
            != evidence.prepared_lease.payload.work_unit_identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = evidence.clone();
    canonical.identity.clear();
    message_identity(
        LEASE_CONSUMPTION_INTENT_RELAY_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn lease_consumption_intent_persistence_v1_identity(
    persistence: &LeaseConsumptionIntentPersistenceV1,
) -> Result<String, ProtocolError> {
    if persistence.schema_version != 1
        || persistence.message_kind != LEASE_CONSUMPTION_INTENT_PERSISTENCE
        || !is_sha256_identity(&persistence.consumption_intent_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = persistence.clone();
    canonical.identity.clear();
    message_identity(
        LEASE_CONSUMPTION_INTENT_PERSISTENCE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn lease_consumption_persistence_v1_identity(
    persistence: &LeaseConsumptionPersistenceV1,
) -> Result<String, ProtocolError> {
    if persistence.schema_version != 1
        || persistence.message_kind != LEASE_CONSUMPTION_PERSISTENCE
        || !is_sha256_identity(&persistence.consumption_admission_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = persistence.clone();
    canonical.identity.clear();
    message_identity(LEASE_CONSUMPTION_PERSISTENCE_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn lease_consumption_relay_evidence_v1_identity(
    evidence: &LeaseConsumptionRelayEvidenceV1,
) -> Result<String, ProtocolError> {
    let prepared_lease_identity = message_identity(
        LEASE_ISSUANCE_DOMAIN_V1.as_bytes(),
        &evidence.prepared_lease,
    )?;
    let consume_request_identity = message_identity(
        LEASE_CONSUME_DOMAIN_V1.as_bytes(),
        &evidence.consume_request,
    )?;
    let consume_response_identity = message_identity(
        LEASE_CONSUME_RESPONSE_DOMAIN_V1.as_bytes(),
        &evidence.consume_response,
    )?;
    if evidence.schema_version != 1
        || !is_sha256_identity(&evidence.authorization_decision_relay_identity)
        || prepared_lease_identity != evidence.prepared_lease_identity
        || consume_request_identity != evidence.consume_request_identity
        || consume_response_identity != evidence.consume_response_identity
        || lease_consumption_admission_v1_identity(&evidence.admission)?
            != evidence.admission.identity
        || evidence.admission.binding_identity != evidence.prepared_lease.payload.binding_identity
        || evidence.admission.prepared_lease_identity != evidence.prepared_lease_identity
        || evidence.admission.consume_request_identity != evidence.consume_request_identity
        || evidence.admission.consume_response_identity != evidence.consume_response_identity
        || evidence.admission.work_unit_identity
            != evidence.prepared_lease.payload.work_unit_identity
        || evidence.admission.work_unit_identity != evidence.consume_request.work_unit_identity
        || evidence.admission.work_unit_identity
            != evidence.consume_response.payload.work_unit_identity
        || evidence.admission.crossing_transaction_id
            != evidence.consume_request.crossing_transaction_id
        || evidence.admission.crossing_transaction_id
            != evidence.consume_response.payload.crossing_transaction_id
        || evidence.admission.crossing_transaction_identity
            != evidence.consume_request.crossing_transaction_identity
        || evidence.admission.crossing_transaction_identity
            != evidence
                .consume_response
                .payload
                .crossing_transaction_identity
        || evidence.consume_request.lease_identity != evidence.prepared_lease_identity
        || evidence.consume_response.payload.lease_identity != evidence.prepared_lease_identity
        || evidence.consume_response.payload.consume_request_identity
            != evidence.consume_request_identity
        || evidence.consume_response.payload.state != LeaseConsumeState::Consumed
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = evidence.clone();
    canonical.identity.clear();
    message_identity(LEASE_CONSUMPTION_RELAY_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_systemd_scope_identity(
    scope: &LauncherSystemdScopeV1,
) -> Result<String, ProtocolError> {
    if scope.schema_version != 1
        || !is_bounded_label(
            scope.invocation_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(scope.request_identity.as_str())
        || !is_sha256_identity(scope.child_identity.as_str())
        || scope.child_pid == 0
        || !is_bounded_label(scope.unit_name.as_str(), 255)
        || !scope.unit_name.starts_with("ota-authority-invocation-")
        || !scope.unit_name.ends_with(".scope")
        || !is_absolute_bounded_path(scope.unit_object_path.as_str(), 1024)
        || scope.slice != "ota-authority-invocations.slice"
        || !is_canonical_absolute_bounded_path(scope.control_group.as_str(), 1024)
        || scope.delegate
        || scope.kill_mode != "control-group"
        || scope.collect_mode != "inactive-or-failed"
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = scope.clone();
    canonical.identity.clear();
    message_identity(LAUNCHER_SYSTEMD_SCOPE_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn protected_launcher_descriptor_v1_identity(
    descriptor: &ProtectedLauncherDescriptorV1,
) -> Result<String, ProtocolError> {
    let role_shape_valid = match descriptor.role {
        ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket => {
            descriptor.kind == ProtectedLauncherDescriptorKindV1::UnixStreamSocket
                && descriptor.access == ProtectedLauncherDescriptorAccessV1::ReadWrite
        }
        ProtectedLauncherDescriptorRoleV1::VerifierStore
        | ProtectedLauncherDescriptorRoleV1::BindingStore => {
            descriptor.kind == ProtectedLauncherDescriptorKindV1::RegularFile
                && descriptor.access == ProtectedLauncherDescriptorAccessV1::ReadOnly
                && descriptor.owner_uid == 0
                && descriptor.owner_gid == 0
                && descriptor.mode == 0o400
                && descriptor
                    .content_identity
                    .as_deref()
                    .is_some_and(is_sha256_identity)
        }
        ProtectedLauncherDescriptorRoleV1::InvocationCgroup => {
            descriptor.kind == ProtectedLauncherDescriptorKindV1::Directory
                && descriptor.access == ProtectedLauncherDescriptorAccessV1::ReadOnly
                && descriptor.owner_uid == 0
                && descriptor.owner_gid == 0
                && descriptor.mode & 0o022 == 0
        }
    };
    if descriptor.schema_version != 1
        || descriptor.inode == 0
        || descriptor.mode > 0o7777
        || matches!(
            descriptor.role,
            ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket
                | ProtectedLauncherDescriptorRoleV1::InvocationCgroup
        ) && descriptor.content_identity.is_some()
        || !role_shape_valid
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = descriptor.clone();
    canonical.identity.clear();
    message_identity(PROTECTED_LAUNCHER_DESCRIPTOR_IDENTITY_DOMAIN_V1, &canonical)
}

#[derive(Serialize)]
struct ProtectedLauncherStoreContentIdentityInputV1<'a> {
    role: ProtectedLauncherDescriptorRoleV1,
    bytes: &'a [u8],
}

pub fn protected_launcher_store_content_identity_v1(
    role: ProtectedLauncherDescriptorRoleV1,
    bytes: &[u8],
) -> Result<String, ProtocolError> {
    if !matches!(
        role,
        ProtectedLauncherDescriptorRoleV1::VerifierStore
            | ProtectedLauncherDescriptorRoleV1::BindingStore
    ) || bytes.is_empty()
        || bytes.len() > MAX_PROTECTED_LAUNCHER_STORE_BYTES_V1
    {
        return Err(ProtocolError::InvalidRecord);
    }
    message_identity(
        PROTECTED_LAUNCHER_STORE_CONTENT_IDENTITY_DOMAIN_V1,
        &ProtectedLauncherStoreContentIdentityInputV1 { role, bytes },
    )
}

#[derive(Serialize)]
struct ProtectedLauncherCgroupIdentityInputV1<'a> {
    scope_identity: &'a str,
    control_group: &'a str,
    descriptor_identity: &'a str,
}

pub fn protected_launcher_cgroup_v1_identity(
    scope: &LauncherSystemdScopeV1,
    descriptor: &ProtectedLauncherDescriptorV1,
) -> Result<String, ProtocolError> {
    if launcher_systemd_scope_identity(scope)? != scope.identity
        || descriptor.role != ProtectedLauncherDescriptorRoleV1::InvocationCgroup
        || protected_launcher_descriptor_v1_identity(descriptor)? != descriptor.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    message_identity(
        PROTECTED_LAUNCHER_CGROUP_IDENTITY_DOMAIN_V1,
        &ProtectedLauncherCgroupIdentityInputV1 {
            scope_identity: scope.identity.as_str(),
            control_group: scope.control_group.as_str(),
            descriptor_identity: descriptor.identity.as_str(),
        },
    )
}

pub fn runner_administrator_authority_v1_identity(
    authority: &RunnerAdministratorAuthorityV1,
) -> Result<String, ProtocolError> {
    if authority.schema_version != 1
        || authority.record_kind != RUNNER_ADMINISTRATOR_AUTHORITY
        || !is_canonical_lowercase_label(
            &authority.authority_id,
            MAX_LAUNCHER_AUTHORITY_ID_BYTES_V1,
        )
        || !is_canonical_nonzero_base64url_32_bytes(&authority.authority_instance_id)
        || authority.administration_scope != "protected_self_hosted_runner"
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = authority.clone();
    canonical.identity.clear();
    message_identity(
        RUNNER_ADMINISTRATOR_AUTHORITY_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn protected_launcher_implementation_subject_v1_identity(
    subject: &ProtectedLauncherImplementationSubjectV1,
) -> Result<String, ProtocolError> {
    let minimum_core =
        Version::parse(&subject.minimum_core_version).map_err(|_| ProtocolError::InvalidRecord)?;
    let maximum_core = Version::parse(&subject.maximum_exclusive_core_version)
        .map_err(|_| ProtocolError::InvalidRecord)?;
    if subject.schema_version != 1
        || subject.record_kind != PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT
        || subject.launcher_source_repository != "https://github.com/ota-run/authority-launcher"
        || subject.core_source_repository != "https://github.com/ota-run/ota"
        || subject.protocol_source_repository != "https://github.com/ota-run/authority-protocol"
        || !is_canonical_git_revision(&subject.launcher_source_revision)
        || !is_canonical_git_revision(&subject.core_source_revision)
        || !is_canonical_git_revision(&subject.protocol_source_revision)
        || !is_sha256_identity(&subject.launcher_build_identity)
        || !is_sha256_identity(&subject.core_build_identity)
        || !is_sha256_identity(&subject.launcher_artifact_identity)
        || !is_sha256_identity(&subject.ota_artifact_identity)
        || subject.protocol_version != SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1
        || !is_canonical_semver(&subject.minimum_core_version)
        || !is_canonical_semver(&subject.maximum_exclusive_core_version)
        || minimum_core >= maximum_core
        || !is_sha256_identity(&subject.launcher_profile_identity)
        || subject.target.environment != "self_hosted"
        || subject.target.os != "linux"
        || subject.target.architecture != "x86_64"
        || subject.target.execution_mode != "native"
        || subject.target.launcher_class != "systemd_protected_launcher_v3"
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = subject.clone();
    canonical.identity.clear();
    message_identity(
        PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn protected_launcher_authority_context_v1_identity(
    context: &ProtectedLauncherAuthorityContextV1,
) -> Result<String, ProtocolError> {
    if context.schema_version != 1
        || context.record_kind != PROTECTED_LAUNCHER_AUTHORITY_CONTEXT
        || runner_administrator_authority_v1_identity(&context.runner_administrator)?
            != context.runner_administrator.identity
        || protected_launcher_implementation_subject_v1_identity(&context.implementation_subject)?
            != context.implementation_subject.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = context.clone();
    canonical.identity.clear();
    message_identity(
        PROTECTED_LAUNCHER_AUTHORITY_CONTEXT_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn protected_launcher_invocation_nonce_v1_identity(
    nonce: &[u8],
) -> Result<String, ProtocolError> {
    if nonce.len() != 32 {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(sha256_identity(&domain_separated(
        PROTECTED_LAUNCHER_INVOCATION_NONCE_IDENTITY_DOMAIN_V1,
        nonce,
    )))
}

pub fn protected_launcher_boot_v1_identity(boot_id: &str) -> Result<String, ProtocolError> {
    if !is_canonical_lowercase_uuid(boot_id) {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(sha256_identity(&domain_separated(
        PROTECTED_LAUNCHER_BOOT_IDENTITY_DOMAIN_V1,
        boot_id.as_bytes(),
    )))
}

pub fn protected_launcher_capability_v1_identity(
    capability: &ProtectedLauncherCapabilityV1,
) -> Result<String, ProtocolError> {
    const REQUIRED_ROLES: [ProtectedLauncherDescriptorRoleV1; 4] = [
        ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket,
        ProtectedLauncherDescriptorRoleV1::VerifierStore,
        ProtectedLauncherDescriptorRoleV1::BindingStore,
        ProtectedLauncherDescriptorRoleV1::InvocationCgroup,
    ];

    if capability.schema_version != 1
        || capability.message_kind != PROTECTED_LAUNCHER_CAPABILITY
        || capability.protocol_version != SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1
        || capability.service_uid != 0
        || capability.service_gid != 0
    {
        return Err(ProtocolError::InvalidRecord);
    }

    for identity in [
        capability.launcher_request_identity.as_str(),
        capability.launcher_executable_identity.as_str(),
        capability.launcher_configuration_identity.as_str(),
        capability.launcher_service_binding_identity.as_str(),
        capability.launcher_profile_identity.as_str(),
        capability.runner_administrator_identity.as_str(),
        capability.invocation_nonce_identity.as_str(),
        capability.boot_identity.as_str(),
        capability.protected_launcher_instance_identity.as_str(),
        capability.systemd_invocation_identity.as_str(),
        capability.systemd_scope_identity.as_str(),
        capability.cgroup_identity.as_str(),
        capability.child_process_identity.as_str(),
        capability.principal_mapping_identity.as_str(),
        capability.process_posture_identity.as_str(),
        capability.implementation_subject_identity.as_str(),
    ] {
        if !is_sha256_identity(identity) {
            return Err(ProtocolError::InvalidRecord);
        }
    }

    if capability.descriptors.len() != REQUIRED_ROLES.len() {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut descriptors = capability.descriptors.clone();
    descriptors.sort_by_key(|descriptor| descriptor.role);
    if descriptors
        .iter()
        .zip(REQUIRED_ROLES)
        .any(|(descriptor, required_role)| {
            descriptor.role != required_role
                || protected_launcher_descriptor_v1_identity(descriptor).as_deref()
                    != Ok(descriptor.identity.as_str())
        })
    {
        return Err(ProtocolError::InvalidRecord);
    }
    if descriptors.iter().enumerate().any(|(index, descriptor)| {
        descriptors[..index].iter().any(|previous| {
            previous.device == descriptor.device && previous.inode == descriptor.inode
        })
    }) {
        return Err(ProtocolError::InvalidRecord);
    }

    let mut canonical = capability.clone();
    canonical.identity.clear();
    canonical.descriptors = descriptors;
    message_identity(PROTECTED_LAUNCHER_CAPABILITY_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn protected_launcher_capability_observation_nonce_commitment_v1(
    nonce: &[u8],
) -> Result<String, ProtocolError> {
    if nonce.len() != 32 {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(sha256_identity(&domain_separated(
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_NONCE_DOMAIN_V1,
        nonce,
    )))
}

pub fn protected_launcher_capability_observation_challenge_v1_identity(
    challenge: &ProtectedLauncherCapabilityObservationChallengeV1,
) -> Result<String, ProtocolError> {
    if challenge.schema_version != 1
        || challenge.message_kind != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE
        || !is_canonical_positive_decimal(&challenge.workflow_run_id)
        || !is_canonical_positive_decimal(&challenge.workflow_run_attempt)
        || !is_canonical_workflow_reference(&challenge.workflow_reference)
        || !is_sha256_identity(&challenge.nonce_commitment)
        || challenge.issued_at_unix_seconds == 0
        || challenge.expires_at_unix_seconds <= challenge.issued_at_unix_seconds
        || challenge.expires_at_unix_seconds - challenge.issued_at_unix_seconds > 300
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = challenge.clone();
    canonical.identity.clear();
    message_identity(
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_protected_launcher_capability_observation_challenge_v1(
    challenge: &ProtectedLauncherCapabilityObservationChallengeV1,
    observed_at_unix_seconds: u64,
) -> Result<(), ProtocolError> {
    if challenge.identity
        != protected_launcher_capability_observation_challenge_v1_identity(challenge)?
        || observed_at_unix_seconds < challenge.issued_at_unix_seconds
        || observed_at_unix_seconds > challenge.expires_at_unix_seconds
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn protected_launcher_capability_observation_request_v1_identity(
    request: &ProtectedLauncherCapabilityObservationRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST
        || !is_canonical_base64url_32_bytes(&request.nonce)
        || !is_canonical_semver(&request.runner_version)
        || !is_sha256_identity(&request.expected_launcher_request_identity)
        || protected_launcher_capability_observation_challenge_v1_identity(&request.challenge)?
            != request.challenge.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&request.nonce)
        .map_err(|_| ProtocolError::InvalidRecord)?;
    if protected_launcher_capability_observation_nonce_commitment_v1(&nonce)?
        != request.challenge.nonce_commitment
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.identity.clear();
    message_identity(
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn protected_launcher_capability_observation_probe_request_v1_identity(
    request: &ProtectedLauncherCapabilityObservationProbeRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROBE_REQUEST
        || request.observation.identity
            != protected_launcher_capability_observation_request_v1_identity(&request.observation)?
        || request.observation.expected_launcher_request_identity
            != launcher_invocation_request_identity(&request.invocation)?
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.identity.clear();
    message_identity(
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROBE_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_protected_launcher_capability_observation_response_v1(
    response: &ProtectedLauncherCapabilityObservationResponseV1,
) -> Result<(), ProtocolError> {
    if response.schema_version != 1
        || response.message_kind != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_RESPONSE
        || !is_sha256_identity(&response.request_identity)
        || response.projection.payload.challenge_identity.is_empty()
    {
        return Err(ProtocolError::InvalidRecord);
    }
    validate_protected_launcher_capability_observation_projection_v1(&response.projection)
}

pub fn protected_launcher_capability_observation_signing_request_v1_identity(
    request: &ProtectedLauncherCapabilityObservationSigningRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_REQUEST
        || !is_sha256_identity(&request.producer_binding_identity)
        || !is_sha256_identity(&request.verifier_identity)
        || !is_sha256_identity(&request.protected_capability_identity)
        || request.projection_identity
            != protected_launcher_capability_observation_projection_v1_identity(&request.payload)?
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.identity.clear();
    message_identity(
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_protected_launcher_capability_observation_signing_request_v1(
    request: &ProtectedLauncherCapabilityObservationSigningRequestV1,
) -> Result<(), ProtocolError> {
    if request.identity
        != protected_launcher_capability_observation_signing_request_v1_identity(request)?
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn validate_protected_launcher_capability_observation_signing_response_v1(
    response: &ProtectedLauncherCapabilityObservationSigningResponseV1,
) -> Result<(), ProtocolError> {
    if response.schema_version != 1
        || response.message_kind != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_RESPONSE
        || !is_sha256_identity(&response.request_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    validate_protected_launcher_capability_observation_projection_v1(&response.projection)
}

pub fn reconcile_protected_launcher_capability_observation_signing_response_v1(
    request: &ProtectedLauncherCapabilityObservationSigningRequestV1,
    response: &ProtectedLauncherCapabilityObservationSigningResponseV1,
) -> Result<(), ProtocolError> {
    validate_protected_launcher_capability_observation_signing_request_v1(request)?;
    validate_protected_launcher_capability_observation_signing_response_v1(response)?;
    if response.request_identity != request.identity
        || response.projection.payload != request.payload
        || response.projection.projection_identity != request.projection_identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn protected_launcher_capability_projection_key_identity_v1(
    public_key: &str,
) -> Result<String, ProtocolError> {
    if !is_canonical_ed25519_public_key(public_key) {
        return Err(ProtocolError::InvalidRecord);
    }
    message_identity(
        PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_KEY_IDENTITY_DOMAIN_V1,
        &public_key,
    )
}

pub fn protected_launcher_capability_observation_projection_v1_identity(
    payload: &ProtectedLauncherCapabilityObservationProjectionPayloadV1,
) -> Result<String, ProtocolError> {
    if payload.schema_version != 1
        || payload.evidence_kind != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION
        || !is_sha256_identity(&payload.challenge_identity)
        || payload.derivation != "verified"
        || payload.target.environment != "self_hosted"
        || payload.target.os != "linux"
        || payload.target.architecture != "x64"
        || payload.capability_class != "systemd_protected_launcher_v3"
        || !is_canonical_semver(&payload.runner_version)
        || !is_sha256_identity(&payload.signing_key_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    message_identity(
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_IDENTITY_DOMAIN_V1,
        payload,
    )
}

pub fn protected_launcher_capability_observation_signature_message_v1(
    projection_identity: &str,
) -> Result<Vec<u8>, ProtocolError> {
    if !is_sha256_identity(projection_identity) {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(domain_separated(
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1,
        projection_identity.as_bytes(),
    ))
}

pub fn validate_protected_launcher_capability_observation_projection_v1(
    projection: &ProtectedLauncherCapabilityObservationProjectionV1,
) -> Result<(), ProtocolError> {
    if projection.projection_identity
        != protected_launcher_capability_observation_projection_v1_identity(&projection.payload)?
        || !is_canonical_ed25519_signature(&projection.signature)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn protected_launcher_capability_projection_verifier_v1_identity(
    verifier: &ProtectedLauncherCapabilityProjectionVerifierV1,
) -> Result<String, ProtocolError> {
    let signature_domain =
        std::str::from_utf8(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1)
            .map_err(|_| ProtocolError::InvalidRecord)?;
    if verifier.schema_version != 1
        || verifier.record_kind != PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER
        || !is_canonical_ed25519_public_key(&verifier.public_key)
        || verifier.key_identity
            != protected_launcher_capability_projection_key_identity_v1(&verifier.public_key)?
        || verifier.key_usage != PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_KEY_USAGE_V1
        || verifier.signature_domain != signature_domain
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = verifier.clone();
    canonical.identity.clear();
    message_identity(
        PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_protected_launcher_capability_projection_verifier_v1(
    verifier: &ProtectedLauncherCapabilityProjectionVerifierV1,
) -> Result<(), ProtocolError> {
    if verifier.identity != protected_launcher_capability_projection_verifier_v1_identity(verifier)?
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

fn canonical_protected_launcher_descriptors(
    descriptors: &[ProtectedLauncherDescriptorV1],
) -> Vec<ProtectedLauncherDescriptorV1> {
    let mut descriptors = descriptors.to_vec();
    descriptors.sort_by_key(|descriptor| descriptor.role);
    descriptors
}

pub fn validate_protected_launcher_capability_v1(
    capability: &ProtectedLauncherCapabilityV1,
    evidence: &ProtectedLauncherCapabilityEvidenceV1<'_>,
) -> Result<(), ProtocolError> {
    if protected_launcher_capability_v1_identity(capability)? != capability.identity {
        return Err(ProtocolError::InvalidRecord);
    }
    validate_launcher_invocation_request_v1(evidence.request)?;
    let request_identity = launcher_invocation_request_identity(evidence.request)?;
    let child_identity = launcher_child_process_identity(evidence.child)?;
    let scope_identity = launcher_systemd_scope_identity(evidence.scope)?;
    let principal_mapping_identity =
        launcher_principal_mapping_identity(evidence.principal_mapping)?;
    let process_posture_identity = ota_process_posture_identity(evidence.process_posture)?;
    validate_systemd_protected_launcher_instance_v3(evidence.launcher_instance)?;

    let observed_descriptors =
        canonical_protected_launcher_descriptors(evidence.observed_descriptors);
    if observed_descriptors != canonical_protected_launcher_descriptors(&capability.descriptors) {
        return Err(ProtocolError::InvalidRecord);
    }
    let verifier_descriptor = observed_descriptors
        .iter()
        .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::VerifierStore)
        .ok_or(ProtocolError::InvalidRecord)?;
    let binding_descriptor = observed_descriptors
        .iter()
        .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::BindingStore)
        .ok_or(ProtocolError::InvalidRecord)?;
    let cgroup_descriptor = observed_descriptors
        .iter()
        .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::InvocationCgroup)
        .ok_or(ProtocolError::InvalidRecord)?;
    let verifier_store_identity = protected_launcher_store_content_identity_v1(
        ProtectedLauncherDescriptorRoleV1::VerifierStore,
        evidence.verifier_store_bytes,
    )?;
    let binding_store_identity = protected_launcher_store_content_identity_v1(
        ProtectedLauncherDescriptorRoleV1::BindingStore,
        evidence.binding_store_bytes,
    )?;
    let cgroup_identity = protected_launcher_cgroup_v1_identity(evidence.scope, cgroup_descriptor)?;

    let instance = &evidence.launcher_instance.instance_v1;
    if capability.launcher_request_identity != request_identity
        || capability.launcher_executable_identity != evidence.launcher_executable_identity
        || capability.launcher_configuration_identity != evidence.launcher_configuration_identity
        || capability.launcher_service_binding_identity
            != evidence.launcher_service_binding_identity
        || capability.launcher_profile_identity != evidence.launcher_profile_identity
        || capability.runner_administrator_identity != evidence.runner_administrator_identity
        || capability.service_uid != evidence.service_uid
        || capability.service_gid != evidence.service_gid
        || capability.invocation_nonce_identity != evidence.invocation_nonce_identity
        || capability.boot_identity != evidence.boot_identity
        || capability.protected_launcher_instance_identity != evidence.launcher_instance.identity
        || capability.systemd_invocation_identity != scope_identity
        || capability.systemd_scope_identity != scope_identity
        || capability.cgroup_identity != cgroup_identity
        || capability.child_process_identity != child_identity
        || capability.principal_mapping_identity != principal_mapping_identity
        || capability.process_posture_identity != process_posture_identity
        || capability.implementation_subject_identity != evidence.implementation_subject_identity
        || evidence.child.identity != child_identity
        || evidence.child.request_identity != request_identity
        || evidence.child.principal_mapping_identity != principal_mapping_identity
        || evidence.scope.identity != scope_identity
        || evidence.scope.request_identity != request_identity
        || evidence.scope.child_identity != child_identity
        || evidence.scope.child_pid != evidence.child.pid
        || evidence.scope.invocation_id != evidence.child.invocation_id
        || evidence.principal_mapping.identity != principal_mapping_identity
        || evidence.process_posture.identity != process_posture_identity
        || evidence.process_posture.pid != evidence.child.pid
        || evidence.process_posture.process_start_time_identity
            != evidence.child.process_start_time_identity
        || evidence.process_posture.ota_binary_identity != evidence.child.ota_binary_identity
        || evidence.process_posture.principal_mapping_identity != principal_mapping_identity
        || instance.principal_mapping != *evidence.principal_mapping
        || instance.process_posture != *evidence.process_posture
        || instance.systemd_launcher_profile_identity != evidence.launcher_profile_identity
        || instance.launcher_session_binding_identity != evidence.launcher_configuration_identity
        || instance.systemd_invocation_identity != scope_identity
        || instance.working_directory_identity != evidence.child.working_directory_identity
        || instance.child_process_identity != child_identity
        || verifier_descriptor.content_identity.as_deref() != Some(verifier_store_identity.as_str())
        || verifier_descriptor.size != evidence.verifier_store_bytes.len() as u64
        || binding_descriptor.content_identity.as_deref() != Some(binding_store_identity.as_str())
        || binding_descriptor.size != evidence.binding_store_bytes.len() as u64
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn launcher_execution_completion_v1_identity(
    completion: &LauncherExecutionCompletionV1,
) -> Result<String, ProtocolError> {
    let valid_exit = match completion.outcome {
        LauncherExecutionOutcomeV1::Completed => completion.exit_code == Some(0),
        LauncherExecutionOutcomeV1::Failed => completion.exit_code.is_some_and(|code| code != 0),
        LauncherExecutionOutcomeV1::Interrupted => completion
            .exit_code
            .is_some_and(|code| matches!(code, 129 | 130 | 131 | 143)),
    };
    if completion.schema_version != 1
        || completion.message_kind != LAUNCHER_EXECUTION_COMPLETION
        || !is_bounded_label(
            completion.invocation_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(&completion.lease_consumption_admission_identity)
        || !is_sha256_identity(&completion.work_unit_identity)
        || !is_bounded_label(
            completion.crossing_transaction_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(&completion.pending_crossing_transaction_identity)
        || !is_sha256_identity(&completion.crossing_transaction_identity)
        || completion
            .receipt_archive_identity
            .as_deref()
            .is_some_and(|identity| !is_sha256_identity(identity))
        || completion.receipt_status.is_empty()
        || completion.receipt_status.len() > 256
        || completion
            .receipt_status
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || !valid_exit
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = completion.clone();
    canonical.identity.clear();
    message_identity(LAUNCHER_EXECUTION_COMPLETION_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_execution_completion_persistence_v1_identity(
    persistence: &LauncherExecutionCompletionPersistenceV1,
) -> Result<String, ProtocolError> {
    if persistence.schema_version != 1
        || persistence.message_kind != LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE
        || !is_sha256_identity(&persistence.completion_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = persistence.clone();
    canonical.identity.clear();
    message_identity(
        LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_execution_finalization_v1_identity(
    finalization: &LauncherExecutionFinalizationV1,
) -> Result<String, ProtocolError> {
    if launcher_execution_completion_v1_identity(&finalization.completion)?
        != finalization.completion.identity
        || !is_sha256_identity(&finalization.child_identity)
        || !is_sha256_identity(&finalization.scope_identity)
        || !finalization.scope_removed
        || !finalization.cgroup_empty_or_absent
        || !finalization.active_slot_removed
    {
        return Err(ProtocolError::InvalidRecord);
    }
    match finalization.schema_version {
        1 => {
            if finalization.child_exit_posture.is_some()
                || finalization.child_absent.is_some()
                || finalization.observed_exit_code != finalization.completion.exit_code
                || !finalization.child_reaped
            {
                return Err(ProtocolError::InvalidRecord);
            }
        }
        2 => match finalization.child_exit_posture {
            Some(LauncherChildExitPostureV1::LauncherObservedAndReaped) => {
                if finalization.observed_exit_code != finalization.completion.exit_code
                    || !finalization.child_reaped
                    || finalization.child_absent != Some(true)
                {
                    return Err(ProtocolError::InvalidRecord);
                }
            }
            Some(LauncherChildExitPostureV1::RecoveredAbsentCompletionBound) => {
                if finalization.observed_exit_code.is_some()
                    || finalization.child_reaped
                    || finalization.child_absent != Some(true)
                {
                    return Err(ProtocolError::InvalidRecord);
                }
            }
            None => return Err(ProtocolError::InvalidRecord),
        },
        _ => return Err(ProtocolError::InvalidRecord),
    }
    let mut canonical = finalization.clone();
    canonical.identity.clear();
    message_identity(
        LAUNCHER_EXECUTION_FINALIZATION_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

#[derive(Serialize)]
struct LauncherExecutionFinalizationSignaturePayloadV1<'a> {
    finalization: &'a LauncherExecutionFinalizationV1,
    producer_binding_identity: &'a str,
    issued_at: &'a str,
}

pub fn launcher_execution_finalization_signature_bytes_v1(
    finalization: &LauncherExecutionFinalizationV1,
    producer_binding_identity: &str,
    issued_at: &str,
) -> Result<Vec<u8>, ProtocolError> {
    if launcher_execution_finalization_v1_identity(finalization)? != finalization.identity
        || !is_sha256_identity(producer_binding_identity)
        || issued_at.is_empty()
        || issued_at.len() > 64
        || issued_at.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let canonical = serde_jcs::to_vec(&LauncherExecutionFinalizationSignaturePayloadV1 {
        finalization,
        producer_binding_identity,
        issued_at,
    })
    .map_err(|_| ProtocolError::InvalidRecord)?;
    Ok(domain_separated(
        LAUNCHER_EXECUTION_FINALIZATION_SIGNATURE_DOMAIN_V1.as_bytes(),
        &canonical,
    ))
}

pub fn signed_launcher_execution_finalization_v1_identity(
    signed: &SignedLauncherExecutionFinalizationV1,
) -> Result<String, ProtocolError> {
    launcher_execution_finalization_signature_bytes_v1(
        &signed.finalization,
        &signed.producer_binding_identity,
        &signed.issued_at,
    )?;
    if signed.schema_version != 1
        || !is_bounded_label(&signed.key_id, 128)
        || signed.algorithm != "ed25519"
        || !is_bounded_label(&signed.signature, 256)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = signed.clone();
    canonical.identity.clear();
    message_identity(
        SIGNED_LAUNCHER_EXECUTION_FINALIZATION_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_archive_sidecar_v1_identity(
    sidecar: &LauncherFinalizationArchiveSidecarV1,
) -> Result<String, ProtocolError> {
    if sidecar.schema_version != 1
        || signed_launcher_execution_finalization_v1_identity(&sidecar.signed_finalization)?
            != sidecar.signed_finalization.identity
        || signed_launcher_finalization_archive_v1_identity(&sidecar.signed_archive)?
            != sidecar.signed_archive.identity
        || sidecar.signed_archive.signed_finalization_identity
            != sidecar.signed_finalization.identity
        || sidecar.signed_archive.crossing_transaction_identity
            != sidecar
                .signed_finalization
                .finalization
                .completion
                .crossing_transaction_identity
        || sidecar
            .signed_finalization
            .finalization
            .completion
            .receipt_archive_identity
            .as_deref()
            .is_some_and(|identity| identity != sidecar.signed_archive.receipt_archive_identity)
        || sidecar.signed_archive.producer_binding_identity
            != sidecar.signed_finalization.producer_binding_identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = sidecar.clone();
    canonical.identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_ARCHIVE_SIDECAR_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

#[derive(Serialize)]
struct LauncherFinalizationArchiveSignaturePayloadV1<'a> {
    signed_finalization_identity: &'a str,
    receipt_archive_identity: &'a str,
    crossing_transaction_identity: &'a str,
    producer_binding_identity: &'a str,
    issued_at: &'a str,
}

pub fn launcher_finalization_archive_signature_bytes_v1(
    signed_archive: &SignedLauncherFinalizationArchiveV1,
) -> Result<Vec<u8>, ProtocolError> {
    if !is_sha256_identity(&signed_archive.signed_finalization_identity)
        || !is_sha256_identity(&signed_archive.receipt_archive_identity)
        || !is_sha256_identity(&signed_archive.crossing_transaction_identity)
        || !is_sha256_identity(&signed_archive.producer_binding_identity)
        || signed_archive.issued_at.is_empty()
        || signed_archive.issued_at.len() > 64
        || signed_archive
            .issued_at
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let canonical = serde_jcs::to_vec(&LauncherFinalizationArchiveSignaturePayloadV1 {
        signed_finalization_identity: &signed_archive.signed_finalization_identity,
        receipt_archive_identity: &signed_archive.receipt_archive_identity,
        crossing_transaction_identity: &signed_archive.crossing_transaction_identity,
        producer_binding_identity: &signed_archive.producer_binding_identity,
        issued_at: &signed_archive.issued_at,
    })
    .map_err(|_| ProtocolError::InvalidRecord)?;
    Ok(domain_separated(
        LAUNCHER_FINALIZATION_ARCHIVE_SIGNATURE_DOMAIN_V1.as_bytes(),
        &canonical,
    ))
}

pub fn signed_launcher_finalization_archive_v1_identity(
    signed_archive: &SignedLauncherFinalizationArchiveV1,
) -> Result<String, ProtocolError> {
    launcher_finalization_archive_signature_bytes_v1(signed_archive)?;
    if signed_archive.schema_version != 1
        || !is_bounded_label(&signed_archive.key_id, 128)
        || signed_archive.algorithm != "ed25519"
        || !is_bounded_label(&signed_archive.signature, 256)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = signed_archive.clone();
    canonical.identity.clear();
    message_identity(
        SIGNED_LAUNCHER_FINALIZATION_ARCHIVE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_launcher_signed_execution_finalization_frame_v1(
    frame: &LauncherSignedExecutionFinalizationFrameV1,
) -> Result<(), ProtocolError> {
    if frame.message_kind != LAUNCHER_SIGNED_EXECUTION_FINALIZATION
        || frame.protocol_version != SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1
        || frame.invocation_id
            != frame
                .signed_finalization
                .finalization
                .completion
                .invocation_id
        || signed_launcher_execution_finalization_v1_identity(&frame.signed_finalization)?
            != frame.signed_finalization.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn launcher_finalization_signing_request_v1_identity(
    request: &LauncherFinalizationSigningRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != LAUNCHER_FINALIZATION_SIGNING_REQUEST
        || launcher_execution_finalization_v1_identity(&request.finalization)?
            != request.finalization.identity
        || !is_sha256_identity(&request.producer_binding_identity)
        || !is_sha256_identity(&request.launcher_service_binding_identity)
        || !is_sha256_identity(&request.launcher_configuration_identity)
        || !is_sha256_identity(&request.launcher_executable_identity)
        || !is_sha256_identity(&request.launcher_profile_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.request_identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_SIGNING_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_signing_response_v1_identity(
    response: &LauncherFinalizationSigningResponseV1,
) -> Result<String, ProtocolError> {
    if response.schema_version != 1
        || response.message_kind != LAUNCHER_FINALIZATION_SIGNING_RESPONSE
        || !is_sha256_identity(&response.request_identity)
        || signed_launcher_execution_finalization_v1_identity(&response.signed_finalization)?
            != response.signed_finalization.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = response.clone();
    canonical.response_identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_SIGNING_RESPONSE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_archive_signing_request_v1_identity(
    request: &LauncherFinalizationArchiveSigningRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_REQUEST
        || signed_launcher_execution_finalization_v1_identity(&request.signed_finalization)?
            != request.signed_finalization.identity
        || !is_sha256_identity(&request.receipt_archive_identity)
        || request.crossing_transaction_identity
            != request
                .signed_finalization
                .finalization
                .completion
                .crossing_transaction_identity
        || request
            .signed_finalization
            .finalization
            .completion
            .receipt_archive_identity
            .as_deref()
            .is_some_and(|identity| identity != request.receipt_archive_identity)
        || request.producer_binding_identity
            != request.signed_finalization.producer_binding_identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.request_identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_archive_signing_response_v1_identity(
    response: &LauncherFinalizationArchiveSigningResponseV1,
) -> Result<String, ProtocolError> {
    if response.schema_version != 1
        || response.message_kind != LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_RESPONSE
        || !is_sha256_identity(&response.request_identity)
        || signed_launcher_finalization_archive_v1_identity(&response.signed_archive)?
            != response.signed_archive.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = response.clone();
    canonical.response_identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_ARCHIVE_SIGNING_RESPONSE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_archive_request_v1_identity(
    request: &LauncherFinalizationArchiveRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != LAUNCHER_FINALIZATION_ARCHIVE_REQUEST
        || !is_bounded_label(&request.authority_id, MAX_LAUNCHER_AUTHORITY_ID_BYTES_V1)
        || !is_sha256_identity(&request.launcher_request_identity)
        || !is_sha256_identity(&request.receipt_archive_identity)
        || !is_sha256_identity(&request.crossing_transaction_identity)
        || request
            .signed_finalization_identity
            .as_deref()
            .is_some_and(|identity| !is_sha256_identity(identity))
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.request_identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_ARCHIVE_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_recovery_request_v1_identity(
    request: &LauncherFinalizationRecoveryRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != LAUNCHER_FINALIZATION_RECOVERY_REQUEST
        || !is_bounded_label(&request.authority_id, MAX_LAUNCHER_AUTHORITY_ID_BYTES_V1)
        || !is_sha256_identity(&request.launcher_request_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.request_identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_RECOVERY_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_archive_response_v1_identity(
    response: &LauncherFinalizationArchiveResponseV1,
) -> Result<String, ProtocolError> {
    if response.schema_version != 1
        || response.message_kind != LAUNCHER_FINALIZATION_ARCHIVE_RESPONSE
        || !is_sha256_identity(&response.request_identity)
        || !is_bounded_label(&response.invocation_id, MAX_LAUNCHER_INVOCATION_ID_BYTES_V1)
        || response.sidecar_file_name.as_deref().is_some_and(|name| {
            name.is_empty()
                || name.len() > 255
                || name.contains('/')
                || name.contains('\\')
                || name.bytes().any(|byte| byte.is_ascii_control())
                || !name.ends_with(".launcher-finalization")
        })
        || launcher_finalization_archive_sidecar_v1_identity(&response.sidecar)?
            != response.sidecar.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = response.clone();
    canonical.response_identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_ARCHIVE_RESPONSE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_finalization_archive_persistence_v1_identity(
    persistence: &LauncherFinalizationArchivePersistenceV1,
) -> Result<String, ProtocolError> {
    if persistence.schema_version != 1
        || persistence.message_kind != LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE
        || !is_sha256_identity(&persistence.request_identity)
        || !is_sha256_identity(&persistence.sidecar_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = persistence.clone();
    canonical.identity.clear();
    message_identity(
        LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_terminal_frame_v1_identity(
    terminal: &LauncherTerminalFrameV1,
) -> Result<String, ProtocolError> {
    validate_launcher_terminal_frame_v1(terminal)?;
    message_identity(LAUNCHER_TERMINAL_FRAME_IDENTITY_DOMAIN_V1, terminal)
}

pub fn launcher_terminal_persistence_v1_identity(
    persistence: &LauncherTerminalPersistenceV1,
) -> Result<String, ProtocolError> {
    if persistence.schema_version != 1
        || persistence.message_kind != LAUNCHER_TERMINAL_PERSISTENCE
        || !is_bounded_label(
            persistence.invocation_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(&persistence.terminal_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = persistence.clone();
    canonical.identity.clear();
    message_identity(LAUNCHER_TERMINAL_PERSISTENCE_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_history_query_v1_identity(
    query: &LauncherHistoryQueryV1,
) -> Result<String, ProtocolError> {
    if query.schema_version != 1
        || query.message_kind != LAUNCHER_HISTORY_QUERY
        || query.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_bounded_label(&query.query_nonce, 128)
        || query
            .archive_identity
            .as_deref()
            .is_some_and(|identity| !is_sha256_identity(identity))
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = query.clone();
    canonical.query_identity.clear();
    message_identity(LAUNCHER_HISTORY_QUERY_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_history_manifest_v1_identity(
    manifest: &LauncherHistoryManifestV1,
) -> Result<String, ProtocolError> {
    let count =
        usize::try_from(manifest.total_selected_count).map_err(|_| ProtocolError::InvalidRecord)?;
    if manifest.schema_version != 1
        || manifest.message_kind != LAUNCHER_HISTORY_MANIFEST
        || manifest.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_sha256_identity(&manifest.query_identity)
        || !is_sha256_identity(&manifest.repository_binding_identity)
        || !is_sha256_identity(&manifest.catalog_namespace_identity)
        || !is_sha256_identity(&manifest.operator_profile_identity)
        || !is_sha256_identity(&manifest.operator_peer_identity)
        || count != manifest.catalog_entry_identities.len()
        || count > MAX_HISTORY_ENTRY_COUNT_V1
        || manifest.bounded_response_bytes > MAX_HISTORY_RESPONSE_BYTES_V1
        || (count == 0) != (manifest.bounded_response_bytes == 0)
        || !is_sha256_identity(&manifest.catalog_snapshot_identity)
        || manifest
            .catalog_entry_identities
            .iter()
            .any(|identity| !is_sha256_identity(identity))
        || has_duplicate_strings(&manifest.catalog_entry_identities)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = manifest.clone();
    canonical.manifest_identity.clear();
    message_identity(LAUNCHER_HISTORY_MANIFEST_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_history_entry_v1_identity(
    entry: &LauncherHistoryEntryV1,
) -> Result<String, ProtocolError> {
    if entry.schema_version != 1
        || entry.message_kind != LAUNCHER_HISTORY_ENTRY
        || entry.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_sha256_identity(&entry.manifest_identity)
        || !is_sha256_identity(&entry.catalog_identity)
        || !is_sha256_identity(&entry.archive_object_identity)
        || !is_sha256_identity(&entry.contract_snapshot_object_identity)
        || !is_sha256_identity(&entry.sidecar_object_identity)
        || entry.archive_object_identity == entry.contract_snapshot_object_identity
        || entry.archive_object_identity == entry.sidecar_object_identity
        || entry.contract_snapshot_object_identity == entry.sidecar_object_identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = entry.clone();
    canonical.entry_identity.clear();
    message_identity(LAUNCHER_HISTORY_ENTRY_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_history_object_v1_identity(
    object: &LauncherHistoryObjectV1,
) -> Result<String, ProtocolError> {
    if object.schema_version != 1
        || object.message_kind != LAUNCHER_HISTORY_OBJECT
        || object.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_sha256_identity(&object.manifest_identity)
        || !is_sha256_identity(&object.catalog_identity)
        || !is_sha256_identity(&object.content_identity)
        || object.byte_length == 0
        || object.byte_length > MAX_HISTORY_RESPONSE_BYTES_V1
        || object.chunk_count == 0
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = object.clone();
    canonical.object_identity.clear();
    message_identity(LAUNCHER_HISTORY_OBJECT_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_history_chunk_v1_identity(
    chunk: &LauncherHistoryChunkV1,
) -> Result<String, ProtocolError> {
    if chunk.schema_version != 1
        || chunk.message_kind != LAUNCHER_HISTORY_CHUNK
        || chunk.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_sha256_identity(&chunk.object_identity)
        || chunk.bytes.is_empty()
        || chunk.bytes.len() > MAX_HISTORY_CHUNK_PAYLOAD_BYTES_V1
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = chunk.clone();
    canonical.chunk_identity.clear();
    message_identity(LAUNCHER_HISTORY_CHUNK_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn launcher_history_pre_query_refusal_v1_identity(
    refusal: &LauncherHistoryPreQueryRefusalV1,
) -> Result<String, ProtocolError> {
    if refusal.schema_version != 1
        || refusal.message_kind != LAUNCHER_HISTORY_PRE_QUERY_REFUSAL
        || refusal.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_bounded_label(&refusal.refusal_nonce, 128)
        || !matches!(
            refusal.reason,
            LauncherHistoryRefusalReasonV1::PeerAdmissionRefused
                | LauncherHistoryRefusalReasonV1::MalformedQuery
                | LauncherHistoryRefusalReasonV1::UnsupportedProtocol
                | LauncherHistoryRefusalReasonV1::ServiceUnavailable
        )
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = refusal.clone();
    canonical.terminal_identity.clear();
    message_identity(
        LAUNCHER_HISTORY_PRE_QUERY_REFUSAL_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_history_query_refusal_v1_identity(
    refusal: &LauncherHistoryQueryRefusalV1,
) -> Result<String, ProtocolError> {
    if refusal.schema_version != 1
        || refusal.message_kind != LAUNCHER_HISTORY_QUERY_REFUSAL
        || refusal.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_sha256_identity(&refusal.query_identity)
        || matches!(
            refusal.reason,
            LauncherHistoryRefusalReasonV1::PeerAdmissionRefused
                | LauncherHistoryRefusalReasonV1::MalformedQuery
                | LauncherHistoryRefusalReasonV1::UnsupportedProtocol
        )
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = refusal.clone();
    canonical.terminal_identity.clear();
    message_identity(
        LAUNCHER_HISTORY_QUERY_REFUSAL_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn launcher_history_manifest_terminal_v1_identity(
    terminal: &LauncherHistoryManifestTerminalV1,
) -> Result<String, ProtocolError> {
    if terminal.schema_version != 1
        || terminal.message_kind != LAUNCHER_HISTORY_MANIFEST_TERMINAL
        || terminal.protocol_version != SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || !is_sha256_identity(&terminal.query_identity)
        || !is_sha256_identity(&terminal.manifest_identity)
        || usize::try_from(terminal.returned_count)
            .map_or(true, |count| count > MAX_HISTORY_ENTRY_COUNT_V1)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = terminal.clone();
    canonical.terminal_identity.clear();
    message_identity(
        LAUNCHER_HISTORY_MANIFEST_TERMINAL_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_launcher_output_frame_v1(
    frame: &LauncherOutputFrameV1,
) -> Result<(), ProtocolError> {
    if frame.message_kind != LAUNCHER_OUTPUT
        || frame.protocol_version != SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1
        || !is_bounded_label(&frame.invocation_id, MAX_LAUNCHER_INVOCATION_ID_BYTES_V1)
        || frame.payload.len() > MAX_LAUNCHER_OUTPUT_PAYLOAD_BYTES_V1
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn validate_launcher_terminal_frame_v1(
    frame: &LauncherTerminalFrameV1,
) -> Result<(), ProtocolError> {
    let selected_stage = matches!(
        frame.stage,
        Some(
            LauncherTerminalStageV1::SelectedExecutionCompletedBoundaryRemoved
                | LauncherTerminalStageV1::SelectedExecutionFailedBoundaryRemoved
                | LauncherTerminalStageV1::SelectedExecutionInterruptedBoundaryRemoved
        )
    );
    let finalization_valid = match (&frame.stage, &frame.finalization) {
        (
            Some(LauncherTerminalStageV1::SelectedExecutionCompletedBoundaryRemoved),
            Some(finalization),
        ) => {
            finalization.completion.outcome == LauncherExecutionOutcomeV1::Completed
                && frame.invocation_id == finalization.completion.invocation_id
                && frame.outcome == LauncherTerminalOutcomeV1::Completed
                && frame.exit_code == Some(0)
                && launcher_execution_finalization_v1_identity(finalization)
                    .ok()
                    .as_deref()
                    == Some(finalization.identity.as_str())
        }
        (
            Some(LauncherTerminalStageV1::SelectedExecutionFailedBoundaryRemoved),
            Some(finalization),
        ) => {
            finalization.completion.outcome == LauncherExecutionOutcomeV1::Failed
                && frame.invocation_id == finalization.completion.invocation_id
                && frame.outcome == LauncherTerminalOutcomeV1::Failed
                && frame.exit_code == finalization.completion.exit_code
                && launcher_execution_finalization_v1_identity(finalization)
                    .ok()
                    .as_deref()
                    == Some(finalization.identity.as_str())
        }
        (
            Some(LauncherTerminalStageV1::SelectedExecutionInterruptedBoundaryRemoved),
            Some(finalization),
        ) => {
            finalization.completion.outcome == LauncherExecutionOutcomeV1::Interrupted
                && frame.invocation_id == finalization.completion.invocation_id
                && frame.outcome == LauncherTerminalOutcomeV1::Cancelled
                && frame.exit_code == finalization.completion.exit_code
                && launcher_execution_finalization_v1_identity(finalization)
                    .ok()
                    .as_deref()
                    == Some(finalization.identity.as_str())
        }
        (_, None) if !selected_stage => true,
        _ => false,
    };
    if frame.message_kind != LAUNCHER_TERMINAL
        || frame.protocol_version != SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1
        || !is_bounded_label(&frame.invocation_id, MAX_LAUNCHER_INVOCATION_ID_BYTES_V1)
        || matches!(frame.outcome, LauncherTerminalOutcomeV1::Completed)
            && frame.exit_code != Some(0)
        || !selected_stage
            && matches!(frame.outcome, LauncherTerminalOutcomeV1::Cancelled)
            && frame.exit_code.is_some()
        || matches!(
            frame.stage,
            Some(
                LauncherTerminalStageV1::RequestRefusedBeforeBoundary
                    | LauncherTerminalStageV1::PostureAdmittedBoundaryRemoved
                    | LauncherTerminalStageV1::AuthorityRefusedBoundaryRemoved
                    | LauncherTerminalStageV1::PreAuthorizationProtocolRefusedBoundaryRemoved
                    | LauncherTerminalStageV1::AttestationAdmittedBeforeAuthorizationBoundaryRemoved
                    | LauncherTerminalStageV1::AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved
                    | LauncherTerminalStageV1::LeaseConsumedBeforeExecutionDisabledBoundaryRemoved
            )
        ) && (frame.outcome != LauncherTerminalOutcomeV1::Refused || frame.exit_code != Some(2))
        || matches!(frame.stage, Some(LauncherTerminalStageV1::BoundaryFailed))
            && (frame.outcome != LauncherTerminalOutcomeV1::Failed || frame.exit_code != Some(1))
        || !finalization_valid
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

fn is_bounded_label(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_absolute_bounded_path(value: &str, maximum_bytes: usize) -> bool {
    value.len() <= maximum_bytes
        && value.starts_with('/')
        && !value.contains('\0')
        && !value.split('/').any(|component| component == "..")
}

fn is_canonical_absolute_bounded_path(value: &str, maximum_bytes: usize) -> bool {
    is_absolute_bounded_path(value, maximum_bytes)
        && value != "/"
        && !value.starts_with("//")
        && !value.ends_with('/')
        && !value
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == ".")
}

fn has_duplicate_strings(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_frame(frame: &[u8]) -> Result<&[u8], ProtocolError> {
    let length_bytes: [u8; 4] = frame
        .get(..4)
        .ok_or(ProtocolError::IncompleteFrame)?
        .try_into()
        .map_err(|_| ProtocolError::IncompleteFrame)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge);
    }
    if frame.len() != 4 + length {
        return Err(ProtocolError::IncompleteFrame);
    }
    Ok(&frame[4..])
}

pub fn domain_separated(domain: &[u8], value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + value.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(value);
    bytes
}

pub fn message_identity<T: Serialize>(domain: &[u8], payload: &T) -> Result<String, ProtocolError> {
    let canonical = serde_jcs::to_vec(payload).map_err(|_| ProtocolError::Canonicalization)?;
    Ok(sha256_identity(&domain_separated(domain, &canonical)))
}

pub fn signed_message_identity<T: Serialize>(
    domain: &[u8],
    message: &SignedBrokerMessage<T>,
) -> Result<String, ProtocolError> {
    message_identity(domain, message)
}

pub fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn protected_launcher_profile_v1() -> RuntimeBoundaryProfileDefinition {
    RuntimeBoundaryProfileDefinition {
        schema_version: RUNTIME_BOUNDARY_SCHEMA_VERSION_V1,
        profile_id: PROTECTED_LAUNCHER_PROFILE_ID_V1.into(),
        attestor_kind: RuntimeBoundaryAttestorKind::ProtectedLauncher,
        observations: vec![
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::JobPrincipalNonRoot,
                RuntimeBoundaryEvidenceMethod::LauncherPrincipalBinding,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::AuthorityBindingWriteDenied,
                RuntimeBoundaryEvidenceMethod::TargetPrincipalAccessCheck,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::AttestorStateWriteDenied,
                RuntimeBoundaryEvidenceMethod::TargetPrincipalAccessCheck,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::BrokerCredentialsAbsentFromJob,
                RuntimeBoundaryEvidenceMethod::LauncherEnvironmentExclusion,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::BrokerCredentialsAbsentFromTask,
                RuntimeBoundaryEvidenceMethod::ChildEnvironmentExclusion,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::BrokerSessionNonInheritable,
                RuntimeBoundaryEvidenceMethod::DescriptorCloexecVerification,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::BrokerSessionNotReacquirable,
                RuntimeBoundaryEvidenceMethod::ProtectedSessionLifetime,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::HostControlSocketUnavailable,
                RuntimeBoundaryEvidenceMethod::TargetPrincipalAccessCheck,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::PrivilegeEscalationUnavailable,
                RuntimeBoundaryEvidenceMethod::LauncherPrivilegePolicy,
                RuntimeBoundarySemanticIdentityPosture::Forbidden,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::LauncherBinaryIdentityBound,
                RuntimeBoundaryEvidenceMethod::ProtectedBinaryMeasurement,
                RuntimeBoundarySemanticIdentityPosture::Required,
            ),
            runtime_boundary_requirement(
                RuntimeBoundaryObservationName::LauncherConfigIdentityBound,
                RuntimeBoundaryEvidenceMethod::ProtectedConfigMeasurement,
                RuntimeBoundarySemanticIdentityPosture::Required,
            ),
        ],
    }
}

pub fn protected_launcher_image_profile_v1() -> RuntimeBoundaryProfileDefinition {
    let mut profile = protected_launcher_profile_v1();
    profile.profile_id = PROTECTED_LAUNCHER_IMAGE_PROFILE_ID_V1.into();
    profile.observations.extend([
        runtime_boundary_requirement(
            RuntimeBoundaryObservationName::RunnerImageIdentityBound,
            RuntimeBoundaryEvidenceMethod::ProtectedImageMeasurement,
            RuntimeBoundarySemanticIdentityPosture::Required,
        ),
        runtime_boundary_requirement(
            RuntimeBoundaryObservationName::HardeningProfileIdentityBound,
            RuntimeBoundaryEvidenceMethod::ProtectedProfileMeasurement,
            RuntimeBoundarySemanticIdentityPosture::Required,
        ),
    ]);
    profile
}

pub fn runtime_boundary_profile_by_id(
    profile_id: &str,
) -> Option<RuntimeBoundaryProfileDefinition> {
    match profile_id {
        PROTECTED_LAUNCHER_PROFILE_ID_V1 => Some(protected_launcher_profile_v1()),
        PROTECTED_LAUNCHER_IMAGE_PROFILE_ID_V1 => Some(protected_launcher_image_profile_v1()),
        _ => None,
    }
}

pub fn runtime_boundary_profile_identity(
    profile: &RuntimeBoundaryProfileDefinition,
) -> Result<String, ProtocolError> {
    message_identity(RUNTIME_BOUNDARY_PROFILE_IDENTITY_DOMAIN_V1, profile)
}

pub fn launcher_attestation_identity_v2(
    attestation: &SignedLauncherAttestationV2,
) -> Result<String, ProtocolError> {
    message_identity(ATTESTATION_IDENTITY_DOMAIN_V2, attestation)
}

pub fn launcher_attestation_identity_v3(
    attestation: &SignedLauncherAttestationV3,
) -> Result<String, ProtocolError> {
    if attestation.payload.attestation_protocol_version
        != SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3
    {
        return Err(ProtocolError::InvalidRecord);
    }
    validate_systemd_protected_launcher_instance_v3(
        &attestation.payload.systemd_protected_launcher,
    )?;
    message_identity(ATTESTATION_IDENTITY_DOMAIN_V3, attestation)
}

pub fn launcher_attestation_claims_v3(
    attestation: &SignedLauncherAttestationV3,
) -> LauncherAttestationClaimsV3 {
    LauncherAttestationClaimsV3 {
        message_kind: attestation.payload.message_kind.clone(),
        attestation_protocol_version: attestation.payload.attestation_protocol_version.clone(),
        binding_identity: attestation.payload.binding_identity.clone(),
        challenge_nonce_commitment: attestation.payload.challenge_nonce_commitment.clone(),
        invocation_id: attestation.payload.invocation_id.clone(),
        work_unit_identity: attestation.payload.work_unit_identity.clone(),
        semantic_scope_identity: attestation.payload.semantic_scope_identity.clone(),
        runner_principal: attestation.payload.runner_principal.clone(),
        channel_delivery: attestation.payload.channel_delivery.clone(),
        authenticated_origin: attestation.payload.authenticated_origin.clone(),
        authority_mounts: attestation.payload.authority_mounts.clone(),
        systemd_protected_launcher: attestation.payload.systemd_protected_launcher.clone(),
        issuer: attestation.payload.issuer.clone(),
        audience: attestation.payload.audience.clone(),
    }
}

pub fn launcher_attestation_claims_v3_identity(
    claims: &LauncherAttestationClaimsV3,
) -> Result<String, ProtocolError> {
    if claims.message_kind != ATTESTATION_RESPONSE
        || claims.attestation_protocol_version != SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3
        || !is_sha256_identity(&claims.binding_identity)
        || !is_sha256_identity(&claims.challenge_nonce_commitment)
        || !is_bounded_label(
            claims.invocation_id.as_str(),
            MAX_LAUNCHER_INVOCATION_ID_BYTES_V1,
        )
        || !is_sha256_identity(&claims.work_unit_identity)
        || !is_sha256_identity(&claims.semantic_scope_identity)
        || claims.runner_principal.is_empty()
        || claims.channel_delivery.is_empty()
        || claims.authenticated_origin.is_empty()
        || claims.authority_mounts.is_empty()
        || claims.issuer.is_empty()
        || claims.audience.is_empty()
    {
        return Err(ProtocolError::InvalidRecord);
    }
    validate_systemd_protected_launcher_instance_v3(&claims.systemd_protected_launcher)?;
    message_identity(LAUNCHER_ATTESTATION_CLAIMS_IDENTITY_DOMAIN_V3, claims)
}

pub fn launcher_attestation_signing_request_v1_identity(
    request: &LauncherAttestationSigningRequestV1,
) -> Result<String, ProtocolError> {
    let claims_identity = launcher_attestation_claims_v3_identity(&request.claims)?;
    if request.schema_version != 1
        || request.message_kind != LAUNCHER_ATTESTATION_SIGNING_REQUEST
        || request.claims_identity != claims_identity
        || request.challenge.message_kind != CHALLENGE_REQUEST
        || request.challenge.protocol_version != PROTOCOL_VERSION_V1
        || request.challenge.binding_identity != request.claims.binding_identity
        || request.challenge.nonce_commitment != request.claims.challenge_nonce_commitment
        || request.challenge.work_unit_identity != request.claims.work_unit_identity
        || request.challenge.semantic_scope_identity != request.claims.semantic_scope_identity
        || request.producer_audience != request.claims.audience
        || request.requested_maximum_validity_seconds == 0
        || [
            &request.launcher_service_binding_identity,
            &request.launcher_configuration_identity,
            &request.launcher_executable_identity,
            &request.launcher_profile_identity,
            &request.producer_binding_identity,
        ]
        .into_iter()
        .any(|identity| !is_sha256_identity(identity))
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = request.clone();
    canonical.request_identity.clear();
    message_identity(
        LAUNCHER_ATTESTATION_SIGNING_REQUEST_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_launcher_attestation_signing_request_v1(
    request: &LauncherAttestationSigningRequestV1,
) -> Result<(), ProtocolError> {
    if request.request_identity != launcher_attestation_signing_request_v1_identity(request)? {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn launcher_attestation_signing_response_v1_identity(
    response: &LauncherAttestationSigningResponseV1,
) -> Result<String, ProtocolError> {
    let projected_claims = launcher_attestation_claims_v3(&response.attestation);
    if response.schema_version != 1
        || response.message_kind != LAUNCHER_ATTESTATION_SIGNING_RESPONSE
        || !is_sha256_identity(&response.request_identity)
        || response.claims_identity != launcher_attestation_claims_v3_identity(&projected_claims)?
        || launcher_attestation_identity_v3(&response.attestation).is_err()
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = response.clone();
    canonical.response_identity.clear();
    message_identity(
        LAUNCHER_ATTESTATION_SIGNING_RESPONSE_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_launcher_attestation_signing_response_v1(
    response: &LauncherAttestationSigningResponseV1,
) -> Result<(), ProtocolError> {
    if response.response_identity != launcher_attestation_signing_response_v1_identity(response)? {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn launcher_attestation_producer_binding_v1_identity(
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<String, ProtocolError> {
    if binding.schema_version != 1
        || !is_bounded_label(&binding.producer_id, 128)
        || binding.socket_path != SYSTEMD_ATTESTOR_SOCKET_PATH_V1
        || binding.service_unit != SYSTEMD_ATTESTOR_SERVICE_UNIT_V1
        || binding.launcher_service_unit != SYSTEMD_LAUNCHER_SERVICE_UNIT_V1
        || !is_sha256_identity(&binding.launcher_service_binding_identity)
        || !is_sha256_identity(&binding.launcher_configuration_identity)
        || !is_sha256_identity(&binding.launcher_profile_identity)
        || !is_sha256_identity(&binding.launcher_executable_identity)
        || !is_sha256_identity(&binding.producer_executable_identity)
        || !is_sha256_identity(&binding.verifier_key_set_identity)
        || !is_bounded_label(&binding.signing_key_id, 128)
        || binding.signing_public_key.len() != 43
        || !binding
            .signing_public_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !is_sha256_identity(&binding.signing_public_key_identity)
        || binding.signing_key_not_before.is_empty()
        || binding.signing_key_not_after.is_empty()
        || binding.issuer.is_empty()
        || binding.audience.is_empty()
        || binding.maximum_attestation_age_seconds == 0
        || binding.maximum_attestation_age_seconds > 3600
        || binding.verifier_maximum_age_seconds == 0
        || binding.verifier_maximum_age_seconds > 3600
        || binding.maximum_attestation_age_seconds > binding.verifier_maximum_age_seconds
        || binding.maximum_request_bytes == 0
        || binding.maximum_request_bytes > MAX_FRAME_BYTES
        || binding.read_write_timeout_seconds == 0
        || binding.read_write_timeout_seconds > 600
        || !is_absolute_bounded_path(&binding.issuance_state_directory, 4096)
        || !is_bounded_label(&binding.signing_credential_name, 128)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let mut canonical = binding.clone();
    canonical.identity.clear();
    message_identity(
        LAUNCHER_ATTESTATION_PRODUCER_BINDING_IDENTITY_DOMAIN_V1,
        &canonical,
    )
}

pub fn validate_launcher_attestation_producer_binding_v1(
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<(), ProtocolError> {
    if binding.identity != launcher_attestation_producer_binding_v1_identity(binding)? {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn launcher_principal_mapping_identity(
    mapping: &LauncherPrincipalMappingV1,
) -> Result<String, ProtocolError> {
    validate_principal_mapping_v1(mapping)?;
    let mut canonical = mapping.clone();
    canonical.identity.clear();
    message_identity(LAUNCHER_PRINCIPAL_MAPPING_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn ota_process_posture_identity(
    posture: &OtaProcessPostureV1,
) -> Result<String, ProtocolError> {
    validate_ota_process_posture_v1(posture)?;
    let mut canonical = posture.clone();
    canonical.identity.clear();
    message_identity(OTA_PROCESS_POSTURE_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn systemd_launcher_profile_v1() -> SystemdLauncherProfileDefinitionV1 {
    SystemdLauncherProfileDefinitionV1 {
        schema_version: 1,
        profile_id: SYSTEMD_LAUNCHER_PROFILE_ID_V1.into(),
        service_settings: vec![
            systemd_setting("User", "root"),
            systemd_setting("Group", "root"),
            systemd_setting("SupplementaryGroups", ""),
            systemd_setting("AmbientCapabilities", ""),
            systemd_setting("UMask", "0077"),
            systemd_setting("NoNewPrivileges", "yes"),
            systemd_setting("RestrictSUIDSGID", "yes"),
            systemd_setting("LockPersonality", "yes"),
            systemd_setting("MemoryDenyWriteExecute", "no"),
            systemd_setting("RestrictRealtime", "yes"),
            systemd_setting("SystemCallArchitectures", "native"),
            systemd_setting("CapabilityBoundingSet", "CAP_SETUID CAP_SETGID CAP_KILL"),
            systemd_setting("PrivateTmp", "yes"),
            systemd_setting("PrivateDevices", "yes"),
            systemd_setting("ProtectSystem", "strict"),
            systemd_setting("ProtectHome", "read-only"),
            systemd_setting("ProtectKernelTunables", "yes"),
            systemd_setting("ProtectKernelModules", "yes"),
            systemd_setting("ProtectKernelLogs", "yes"),
            systemd_setting("ProtectClock", "yes"),
            systemd_setting("ProtectControlGroups", "yes"),
            systemd_setting("ProtectProc", "invisible"),
            systemd_setting("ProcSubset", "pid"),
            systemd_setting("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            systemd_setting("RestrictNamespaces", "yes"),
            systemd_setting(
                "ReadOnlyPaths",
                "/etc/ota <installation_manifest> <unit_and_dropin_files> <launcher_and_ota_executables> <encrypted_credential_source> <broker_proxy_socket_metadata> <service_credential_directory>",
            ),
            systemd_setting(
                "ReadWritePaths",
                "/run/ota/authority-launcher /var/lib/ota/authority-launcher <allowed_repository_roots>",
            ),
            systemd_setting(
                "LoadCredentialEncrypted",
                "<attestor_credential_name>:<encrypted_attestor_credential_source>",
            ),
            systemd_setting("KillMode", "control-group"),
        ],
        socket_settings: vec![
            systemd_setting("Accept", "no"),
            systemd_setting("ListenStream", "/run/ota/authority-launcher.sock"),
            systemd_setting("SocketUser", "root"),
            systemd_setting("SocketGroup", "<job_peer_gid>"),
            systemd_setting("SocketMode", "0660"),
            systemd_setting("RemoveOnStop", "yes"),
            systemd_setting("Service", "ota-authority-launcher.service"),
        ],
        invocation_scope_settings: vec![
            systemd_setting("Slice", "ota-authority-invocations.slice"),
            systemd_setting("PIDs", "<stopped_child_pid>"),
            systemd_setting("Delegate", "no"),
            systemd_setting("KillMode", "control-group"),
            systemd_setting("CollectMode", "inactive-or-failed"),
        ],
        evidence_sources: vec![
            SystemdLauncherEvidenceSource::ProtectedFileIdentity,
            SystemdLauncherEvidenceSource::SystemdManagerProperty,
            SystemdLauncherEvidenceSource::SocketPeerCredentials,
            SystemdLauncherEvidenceSource::ProcProcessStatus,
            SystemdLauncherEvidenceSource::ProcDescriptorInspection,
            SystemdLauncherEvidenceSource::ProcUnixSocketInspection,
            SystemdLauncherEvidenceSource::TargetPrincipalAccessProbe,
            SystemdLauncherEvidenceSource::OtaProcessPosture,
        ],
    }
}

/// Launcher profile with attestation signing isolated in the protected producer service.
///
/// The definition wire schema remains V1; `profile_id` and content identity distinguish this
/// additive profile from the legacy launcher-owned credential posture.
pub fn systemd_launcher_profile_v2() -> SystemdLauncherProfileDefinitionV1 {
    let mut profile = systemd_launcher_profile_v1();
    profile.profile_id = SYSTEMD_LAUNCHER_PROFILE_ID_V2.into();
    profile.service_settings.retain(|setting| {
        !matches!(
            setting.name.as_str(),
            "ReadOnlyPaths" | "LoadCredentialEncrypted"
        )
    });
    profile.service_settings.push(systemd_setting(
        "ReadOnlyPaths",
        "/etc/ota <installation_manifest> <unit_and_dropin_files> <launcher_and_ota_executables> <producer_public_verifier_set> <producer_socket_metadata> <broker_proxy_socket_metadata>",
    ));
    profile
}

/// Separated-producer profile with the bounded process-inspection capability required while
/// `ProtectProc=invisible` remains active.
pub fn systemd_launcher_profile_v3() -> SystemdLauncherProfileDefinitionV1 {
    let mut profile = systemd_launcher_profile_v2();
    profile.profile_id = SYSTEMD_LAUNCHER_PROFILE_ID_V3.into();
    let restrict_suid_sgid = profile
        .service_settings
        .iter_mut()
        .find(|setting| setting.name == "RestrictSUIDSGID")
        .expect("canonical systemd launcher profile carries a set-ID restriction posture");
    // systemd's RestrictSUIDSGID filter blocks openat2 on supported pressure hosts. The launcher
    // keeps race-resistant openat2 resolution and relies on NoNewPrivileges, ProtectSystem, and
    // exact writable-path controls; selected execution retains its separate stricter posture.
    restrict_suid_sgid.value = "no".into();
    let ambient_capabilities = profile
        .service_settings
        .iter_mut()
        .find(|setting| setting.name == "AmbientCapabilities")
        .expect("canonical systemd launcher profile carries an ambient capability posture");
    // The root launcher performs one verified setresuid transition for its target-principal
    // helper. systemd otherwise removes CAP_SETUID from the effective set while applying this
    // profile's sandbox. The non-root transition clears the ambient capability before selected
    // code can execute.
    ambient_capabilities.value = "CAP_SETUID".into();
    let socket_source = profile
        .evidence_sources
        .iter_mut()
        .find(|source| **source == SystemdLauncherEvidenceSource::ProcUnixSocketInspection)
        .expect("canonical systemd launcher profile carries socket identity evidence");
    *socket_source = SystemdLauncherEvidenceSource::ProtectedSocketIdentity;
    let capability_bounding_set = profile
        .service_settings
        .iter_mut()
        .find(|setting| setting.name == "CapabilityBoundingSet")
        .expect("canonical systemd launcher profile carries a capability boundary");
    capability_bounding_set.value =
        "CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_PTRACE CAP_DAC_OVERRIDE".into();
    let read_only_paths = profile
        .service_settings
        .iter_mut()
        .find(|setting| setting.name == "ReadOnlyPaths")
        .expect("canonical systemd launcher profile carries read-only paths");
    read_only_paths
        .value
        .push_str(" <systemd_runtime_configuration>");
    profile
}

pub fn systemd_launcher_profile_by_id(
    profile_id: &str,
) -> Option<SystemdLauncherProfileDefinitionV1> {
    match profile_id {
        SYSTEMD_LAUNCHER_PROFILE_ID_V1 => Some(systemd_launcher_profile_v1()),
        SYSTEMD_LAUNCHER_PROFILE_ID_V2 => Some(systemd_launcher_profile_v2()),
        SYSTEMD_LAUNCHER_PROFILE_ID_V3 => Some(systemd_launcher_profile_v3()),
        _ => None,
    }
}

pub fn systemd_job_principal_profile_v1() -> SystemdJobPrincipalProfileDefinitionV1 {
    use SystemdJobPrincipalEvidenceMethod as Evidence;
    use SystemdJobPrincipalRequirement as Requirement;

    SystemdJobPrincipalProfileDefinitionV1 {
        schema_version: 1,
        profile_id: SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1.into(),
        requirements: vec![
            job_principal_requirement(
                Requirement::DistinctOneToOnePrincipals,
                &[
                    Evidence::ProtectedMappingConfiguration,
                    Evidence::ProcPeerStatus,
                    Evidence::AccountDatabaseInspection,
                ],
            ),
            job_principal_requirement(
                Requirement::PeerIdentityMatchesProtectedMapping,
                &[
                    Evidence::ProtectedMappingConfiguration,
                    Evidence::ProcPeerStatus,
                ],
            ),
            job_principal_requirement(
                Requirement::PeerNoNewPrivileges,
                &[Evidence::ProcPeerStatus],
            ),
            job_principal_requirement(
                Requirement::PeerCapabilitiesEmpty,
                &[Evidence::ProcPeerStatus],
            ),
            job_principal_requirement(
                Requirement::PeerSupplementaryGroupsEmpty,
                &[Evidence::ProcPeerStatus],
            ),
            job_principal_requirement(
                Requirement::RunnerServiceIdentityBound,
                &[Evidence::ProtectedRunnerServiceIdentity],
            ),
            job_principal_requirement(
                Requirement::AllPrincipalProcessesContained,
                &[Evidence::ProcPrincipalCgroupEnumeration],
            ),
            job_principal_requirement(
                Requirement::AccountsLocked,
                &[Evidence::AccountDatabaseInspection],
            ),
            job_principal_requirement(
                Requirement::NonLoginShells,
                &[Evidence::AccountDatabaseInspection],
            ),
            job_principal_requirement(Requirement::SudoPolicyDenied, &[Evidence::SudoPolicyQuery]),
            job_principal_requirement(
                Requirement::SystemdPolicyDenied,
                &[Evidence::SystemdManagerAuthorizationQuery],
            ),
            job_principal_requirement(
                Requirement::PolkitPolicyDenied,
                &[Evidence::PolkitAuthorizationQuery],
            ),
            job_principal_requirement(
                Requirement::ProtectedPathsWriteDenied,
                &[Evidence::TargetPrincipalAccessProbe],
            ),
            job_principal_requirement(
                Requirement::HostControlSocketsDenied,
                &[Evidence::TargetPrincipalAccessProbe],
            ),
            job_principal_requirement(
                Requirement::ExecutionLauncherSocketDenied,
                &[Evidence::TargetPrincipalAccessProbe],
            ),
            job_principal_requirement(
                Requirement::OtaProcessNonDumpable,
                &[Evidence::OtaProcessPosture, Evidence::ProcessAccessProbe],
            ),
            job_principal_requirement(
                Requirement::OtaPtracerCleared,
                &[Evidence::OtaProcessPosture, Evidence::ProcessAccessProbe],
            ),
            job_principal_requirement(
                Requirement::OtaProcessInspectionDenied,
                &[Evidence::ProcessAccessProbe],
            ),
        ],
    }
}

/// Job-principal profile compatible with systemd's representation of the primary GID in the
/// kernel supplementary-group vector. It permits no group other than the protected primary GID.
pub fn systemd_job_principal_profile_v2() -> SystemdJobPrincipalProfileDefinitionV1 {
    let mut profile = systemd_job_principal_profile_v1();
    profile.profile_id = SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2.into();
    let supplementary_groups = profile
        .requirements
        .iter_mut()
        .find(|requirement| {
            requirement.requirement == SystemdJobPrincipalRequirement::PeerSupplementaryGroupsEmpty
        })
        .expect("canonical job-principal profile carries a supplementary-group requirement");
    supplementary_groups.requirement =
        SystemdJobPrincipalRequirement::PeerSupplementaryGroupsLimitedToPrimary;
    profile
}

pub fn systemd_job_principal_profile_by_id(
    profile_id: &str,
) -> Option<SystemdJobPrincipalProfileDefinitionV1> {
    match profile_id {
        SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1 => Some(systemd_job_principal_profile_v1()),
        SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2 => Some(systemd_job_principal_profile_v2()),
        _ => None,
    }
}

pub fn systemd_launcher_profile_identity(
    profile: &SystemdLauncherProfileDefinitionV1,
) -> Result<String, ProtocolError> {
    message_identity(SYSTEMD_LAUNCHER_PROFILE_IDENTITY_DOMAIN_V1, profile)
}

pub fn systemd_job_principal_profile_identity(
    profile: &SystemdJobPrincipalProfileDefinitionV1,
) -> Result<String, ProtocolError> {
    message_identity(SYSTEMD_JOB_PRINCIPAL_PROFILE_IDENTITY_DOMAIN_V1, profile)
}

pub fn systemd_protected_launcher_instance_identity(
    instance: &SystemdProtectedLauncherInstanceEvidenceV1,
) -> Result<String, ProtocolError> {
    validate_systemd_protected_launcher_instance_v1(instance)?;
    let mut canonical = instance.clone();
    canonical.identity.clear();
    message_identity(SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V1, &canonical)
}

pub fn systemd_protected_launcher_instance_v2_identity(
    instance: &SystemdProtectedLauncherInstanceEvidenceV2,
) -> Result<String, ProtocolError> {
    validate_systemd_protected_launcher_instance_v2(instance)?;
    let mut canonical = instance.clone();
    canonical.identity.clear();
    let domain = match instance.schema_version {
        2 => SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V2,
        3 => SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V3,
        _ => return Err(ProtocolError::InvalidRecord),
    };
    message_identity(domain, &canonical)
}

fn runtime_boundary_requirement(
    name: RuntimeBoundaryObservationName,
    evidence_method: RuntimeBoundaryEvidenceMethod,
    semantic_identity: RuntimeBoundarySemanticIdentityPosture,
) -> RuntimeBoundaryObservationRequirement {
    RuntimeBoundaryObservationRequirement {
        name,
        evidence_method,
        semantic_identity,
    }
}

fn systemd_setting(name: &str, value: &str) -> SystemdProfileSetting {
    SystemdProfileSetting {
        name: name.into(),
        value: value.into(),
    }
}

fn job_principal_requirement(
    requirement: SystemdJobPrincipalRequirement,
    evidence_methods: &[SystemdJobPrincipalEvidenceMethod],
) -> SystemdJobPrincipalRequirementDefinition {
    SystemdJobPrincipalRequirementDefinition {
        requirement,
        evidence_methods: evidence_methods.to_vec(),
    }
}

fn validate_principal_mapping_v1(
    mapping: &LauncherPrincipalMappingV1,
) -> Result<(), ProtocolError> {
    if mapping.schema_version != 1
        || !principal_is_uniform_non_root(&mapping.job_peer)
        || !principal_is_uniform_non_root(&mapping.execution)
        || mapping.job_peer.real_uid == mapping.execution.real_uid
        || mapping.job_peer.real_gid == mapping.execution.real_gid
        || !is_sha256_identity(&mapping.job_principal_profile_identity)
        || !is_sha256_identity(&mapping.launcher_session_binding_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

fn validate_ota_process_posture_v1(posture: &OtaProcessPostureV1) -> Result<(), ProtocolError> {
    if posture.schema_version != 1
        || posture.message_kind != OTA_PROCESS_POSTURE
        || posture.pid == 0
        || !is_sha256_identity(&posture.process_start_time_identity)
        || !is_sha256_identity(&posture.ota_binary_identity)
        || !posture.no_new_privs
        || posture.dumpable != 0
        || !posture.ptracer_clear_applied
        || !is_sha256_identity(&posture.principal_mapping_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

fn validate_systemd_protected_launcher_instance_v1(
    instance: &SystemdProtectedLauncherInstanceEvidenceV1,
) -> Result<(), ProtocolError> {
    validate_systemd_protected_launcher_instance_foundation(instance, false)
}

fn validate_systemd_protected_launcher_instance_v3_foundation(
    instance: &SystemdProtectedLauncherInstanceEvidenceV1,
) -> Result<(), ProtocolError> {
    validate_systemd_protected_launcher_instance_foundation(instance, true)
}

/// Derive the nested foundation identity for the exact V3 launcher and V2 job-principal branch.
/// Legacy callers must continue using `systemd_protected_launcher_instance_identity`.
pub fn systemd_protected_launcher_instance_v3_foundation_identity(
    instance: &SystemdProtectedLauncherInstanceEvidenceV1,
) -> Result<String, ProtocolError> {
    validate_systemd_protected_launcher_instance_v3_foundation(instance)?;
    let mut canonical = instance.clone();
    canonical.identity.clear();
    message_identity(SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V1, &canonical)
}

fn validate_systemd_protected_launcher_instance_foundation(
    instance: &SystemdProtectedLauncherInstanceEvidenceV1,
    v3: bool,
) -> Result<(), ProtocolError> {
    let mapping_identity = launcher_principal_mapping_identity(&instance.principal_mapping)?;
    let posture_identity = ota_process_posture_identity(&instance.process_posture)?;
    let launcher_profiles = if v3 {
        vec![systemd_launcher_profile_v3()]
    } else {
        vec![systemd_launcher_profile_v1(), systemd_launcher_profile_v2()]
    };
    let launcher_profile = launcher_profiles
        .into_iter()
        .find(|profile| {
            systemd_launcher_profile_identity(profile).as_deref()
                == Ok(instance.systemd_launcher_profile_identity.as_str())
        })
        .ok_or(ProtocolError::InvalidRecord)?;
    let launcher_profile_identity = systemd_launcher_profile_identity(&launcher_profile)?;
    let job_profiles = if v3 {
        vec![systemd_job_principal_profile_v2()]
    } else {
        vec![systemd_job_principal_profile_v1()]
    };
    let job_profile = job_profiles
        .into_iter()
        .find(|profile| {
            systemd_job_principal_profile_identity(profile).as_deref()
                == Ok(instance.systemd_job_principal_profile_identity.as_str())
        })
        .ok_or(ProtocolError::InvalidRecord)?;
    let job_profile_identity = systemd_job_principal_profile_identity(&job_profile)?;
    let expected_job_profile_id = if v3 {
        SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2
    } else {
        SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1
    };
    if instance.schema_version != 1
        || instance.adapter != SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1
        || instance.principal_mapping.identity != mapping_identity
        || instance.process_posture.identity != posture_identity
        || instance.process_posture.principal_mapping_identity != mapping_identity
        || instance.systemd_launcher_profile_identity != launcher_profile_identity
        || job_profile.profile_id != expected_job_profile_id
        || instance.systemd_job_principal_profile_identity != job_profile_identity
        || instance.principal_mapping.job_principal_profile_identity != job_profile_identity
        || instance.launcher_session_binding_identity
            != instance.principal_mapping.launcher_session_binding_identity
        || !is_sha256_identity(&instance.systemd_invocation_identity)
        || !is_sha256_identity(&instance.working_directory_identity)
        || !is_sha256_identity(&instance.child_process_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

fn validate_systemd_protected_launcher_instance_v2(
    instance: &SystemdProtectedLauncherInstanceEvidenceV2,
) -> Result<(), ProtocolError> {
    let (launcher_profile, job_profile) = match instance.schema_version {
        2 => {
            validate_systemd_protected_launcher_instance_v1(&instance.instance_v1)?;
            if instance.instance_v1.identity
                != systemd_protected_launcher_instance_identity(&instance.instance_v1)?
            {
                return Err(ProtocolError::InvalidRecord);
            }
            let launcher_profile = [systemd_launcher_profile_v1(), systemd_launcher_profile_v2()]
                .into_iter()
                .find(|profile| {
                    systemd_launcher_profile_identity(profile).as_deref()
                        == Ok(instance
                            .instance_v1
                            .systemd_launcher_profile_identity
                            .as_str())
                })
                .ok_or(ProtocolError::InvalidRecord)?;
            (launcher_profile, systemd_job_principal_profile_v1())
        }
        3 => {
            let foundation_identity =
                systemd_protected_launcher_instance_v3_foundation_identity(&instance.instance_v1)?;
            if instance.instance_v1.identity != foundation_identity {
                return Err(ProtocolError::InvalidRecord);
            }
            (
                systemd_launcher_profile_v3(),
                systemd_job_principal_profile_v2(),
            )
        }
        _ => return Err(ProtocolError::InvalidRecord),
    };
    if instance.launcher_observations.len() != launcher_profile.evidence_sources.len()
        || instance
            .launcher_observations
            .iter()
            .zip(launcher_profile.evidence_sources.iter())
            .any(|(observed, required)| {
                observed.source != *required
                    || observed.state != RuntimeBoundaryObservationState::Verified
                    || !is_reason_code(&observed.reason_code)
                    || match (&observed.evidence_identity, instance.schema_version) {
                        (None, 2) => false,
                        (Some(identity), 3) => !is_sha256_identity(identity),
                        _ => true,
                    }
            })
    {
        return Err(ProtocolError::InvalidRecord);
    }
    if instance.job_principal_observations.len() != job_profile.requirements.len()
        || instance
            .job_principal_observations
            .iter()
            .zip(job_profile.requirements.iter())
            .any(|(observed, required)| {
                observed.requirement != required.requirement
                    || observed.evidence_methods != required.evidence_methods
                    || observed.state != RuntimeBoundaryObservationState::Verified
                    || !is_reason_code(&observed.reason_code)
                    || match (&observed.evidence_identity, instance.schema_version) {
                        (None, 2) => false,
                        (Some(identity), 3) => !is_sha256_identity(identity),
                        _ => true,
                    }
            })
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

fn validate_systemd_protected_launcher_instance_v3(
    instance: &SystemdProtectedLauncherInstanceEvidenceV2,
) -> Result<(), ProtocolError> {
    validate_systemd_protected_launcher_instance_v2(instance)?;
    let launcher_profile_identity =
        systemd_launcher_profile_identity(&systemd_launcher_profile_v3())?;
    let job_profile_identity =
        systemd_job_principal_profile_identity(&systemd_job_principal_profile_v2())?;
    if instance.schema_version != 3
        || instance.identity != systemd_protected_launcher_instance_v2_identity(instance)?
        || instance.instance_v1.systemd_launcher_profile_identity != launcher_profile_identity
        || instance.instance_v1.systemd_job_principal_profile_identity != job_profile_identity
        || instance
            .instance_v1
            .principal_mapping
            .job_principal_profile_identity
            != job_profile_identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

fn principal_is_uniform_non_root(principal: &UnixPrincipalIdentity) -> bool {
    principal.real_uid != 0
        && principal.real_gid != 0
        && principal.real_uid == principal.effective_uid
        && principal.real_uid == principal.saved_uid
        && principal.real_uid == principal.filesystem_uid
        && principal.real_gid == principal.effective_gid
        && principal.real_gid == principal.saved_gid
        && principal.real_gid == principal.filesystem_gid
}

fn is_sha256_identity(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_git_revision(value: &str) -> bool {
    value.len() == 40
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_canonical_lowercase_label(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn is_canonical_lowercase_uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
}

fn is_base64url_no_pad(value: &str, exact_len: usize) -> bool {
    value.len() == exact_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_canonical_base64url_32_bytes(value: &str) -> bool {
    is_base64url_no_pad(value, 43)
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}

fn is_canonical_nonzero_base64url_32_bytes(value: &str) -> bool {
    is_canonical_base64url_32_bytes(value)
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.iter().any(|byte| *byte != 0))
}

fn is_canonical_ed25519_public_key(value: &str) -> bool {
    is_base64url_no_pad(value, 43)
        && value.as_bytes().last().is_some_and(|byte| {
            matches!(
                byte,
                b'A' | b'E'
                    | b'I'
                    | b'M'
                    | b'Q'
                    | b'U'
                    | b'Y'
                    | b'c'
                    | b'g'
                    | b'k'
                    | b'o'
                    | b's'
                    | b'w'
                    | b'0'
                    | b'4'
                    | b'8'
            )
        })
}

fn is_canonical_ed25519_signature(value: &str) -> bool {
    is_base64url_no_pad(value, 86)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| matches!(byte, b'A' | b'Q' | b'g' | b'w'))
}

fn is_canonical_positive_decimal(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|parsed| parsed > 0 && value == parsed.to_string())
}

fn is_canonical_semver(value: &str) -> bool {
    value.len() <= 128 && Version::parse(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn is_canonical_workflow_reference(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 512
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    let Some((workflow_path, git_ref)) = value.split_once('@') else {
        return false;
    };
    if git_ref.contains('@') {
        return false;
    }
    let Some(ref_name) = git_ref
        .strip_prefix("refs/heads/")
        .or_else(|| git_ref.strip_prefix("refs/tags/"))
    else {
        return false;
    };
    if ref_name.is_empty()
        || ref_name.starts_with('.')
        || ref_name.ends_with('.')
        || ref_name.contains("..")
        || ref_name.contains("@{")
        || !ref_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        || ref_name.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || matches!(component, "." | "..")
                || component.ends_with(".lock")
        })
    {
        return false;
    }
    let segments = workflow_path.split('/').collect::<Vec<_>>();
    segments.len() == 5
        && is_canonical_github_owner(segments[0])
        && is_canonical_github_repository(segments[1])
        && segments[2] == ".github"
        && segments[3] == "workflows"
        && segments[4..].iter().all(|segment| {
            !segment.is_empty()
                && !segment.starts_with('.')
                && *segment != "."
                && *segment != ".."
                && segment.len() <= 128
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        && (workflow_path.ends_with(".yml") || workflow_path.ends_with(".yaml"))
        && !git_ref.ends_with('/')
}

fn is_canonical_github_owner(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 39
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn is_canonical_github_repository(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn is_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'-')
        })
}

pub fn nonce_commitment(nonce: &[u8]) -> String {
    sha256_identity(&domain_separated(CHALLENGE_IDENTITY_DOMAIN_V1, nonce))
}

pub fn derive_work_unit_identity(
    binding_identity: &str,
    contract_identity: &str,
    semantic_scope_identity: &str,
    nonce_commitment: &str,
) -> Result<String, ProtocolError> {
    let canonical = serde_jcs::to_vec(&(
        binding_identity,
        contract_identity,
        semantic_scope_identity,
        nonce_commitment,
    ))
    .map_err(|_| ProtocolError::Canonicalization)?;
    Ok(sha256_identity(&domain_separated(
        WORK_UNIT_IDENTITY_DOMAIN_V1,
        &canonical,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER_STORE_BYTES: &[u8] = br#"{"schema_version":1,"verifiers":[]}"#;
    const BINDING_STORE_BYTES: &[u8] = br#"{"schema_version":1,"bindings":[]}"#;

    fn protected_launcher_authority_context() -> ProtectedLauncherAuthorityContextV1 {
        let digest = |character: char| format!("sha256:{}", character.to_string().repeat(64));
        let mut runner_administrator = RunnerAdministratorAuthorityV1 {
            schema_version: 1,
            record_kind: RUNNER_ADMINISTRATOR_AUTHORITY.into(),
            identity: String::new(),
            authority_id: "ota-runner-administrator".into(),
            authority_instance_id: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            administration_scope: "protected_self_hosted_runner".into(),
        };
        runner_administrator.identity =
            runner_administrator_authority_v1_identity(&runner_administrator)
                .expect("runner administrator identity");
        let mut implementation_subject = ProtectedLauncherImplementationSubjectV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT.into(),
            identity: String::new(),
            launcher_source_repository: "https://github.com/ota-run/authority-launcher".into(),
            launcher_source_revision: "a".repeat(40),
            core_source_repository: "https://github.com/ota-run/ota".into(),
            core_source_revision: "b".repeat(40),
            protocol_source_repository: "https://github.com/ota-run/authority-protocol".into(),
            protocol_source_revision: "c".repeat(40),
            launcher_build_identity: digest('1'),
            core_build_identity: digest('2'),
            launcher_artifact_identity: digest('3'),
            ota_artifact_identity: digest('4'),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            minimum_core_version: "1.6.28".into(),
            maximum_exclusive_core_version: "1.7.0".into(),
            launcher_profile_identity: digest('5'),
            target: ProtectedLauncherImplementationTargetV1 {
                environment: "self_hosted".into(),
                os: "linux".into(),
                architecture: "x86_64".into(),
                execution_mode: "native".into(),
                launcher_class: "systemd_protected_launcher_v3".into(),
            },
        };
        implementation_subject.identity =
            protected_launcher_implementation_subject_v1_identity(&implementation_subject)
                .expect("implementation subject identity");
        let mut context = ProtectedLauncherAuthorityContextV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_AUTHORITY_CONTEXT.into(),
            identity: String::new(),
            runner_administrator,
            implementation_subject,
        };
        context.identity = protected_launcher_authority_context_v1_identity(&context)
            .expect("authority context identity");
        context
    }

    fn protected_descriptor(
        role: ProtectedLauncherDescriptorRoleV1,
        seed: u64,
    ) -> ProtectedLauncherDescriptorV1 {
        let (kind, access, owner_gid, mode, size) = match role {
            ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket => (
                ProtectedLauncherDescriptorKindV1::UnixStreamSocket,
                ProtectedLauncherDescriptorAccessV1::ReadWrite,
                995,
                0o660,
                0,
            ),
            ProtectedLauncherDescriptorRoleV1::VerifierStore
            | ProtectedLauncherDescriptorRoleV1::BindingStore => (
                ProtectedLauncherDescriptorKindV1::RegularFile,
                ProtectedLauncherDescriptorAccessV1::ReadOnly,
                0,
                0o400,
                match role {
                    ProtectedLauncherDescriptorRoleV1::VerifierStore => {
                        VERIFIER_STORE_BYTES.len() as u64
                    }
                    ProtectedLauncherDescriptorRoleV1::BindingStore => {
                        BINDING_STORE_BYTES.len() as u64
                    }
                    _ => unreachable!(),
                },
            ),
            ProtectedLauncherDescriptorRoleV1::InvocationCgroup => (
                ProtectedLauncherDescriptorKindV1::Directory,
                ProtectedLauncherDescriptorAccessV1::ReadOnly,
                0,
                0o755,
                0,
            ),
        };
        let mut descriptor = ProtectedLauncherDescriptorV1 {
            schema_version: 1,
            identity: String::new(),
            role,
            kind,
            access,
            device: seed,
            inode: 1000 + seed,
            owner_uid: 0,
            owner_gid,
            mode,
            size,
            content_identity: match role {
                ProtectedLauncherDescriptorRoleV1::VerifierStore => Some(
                    protected_launcher_store_content_identity_v1(role, VERIFIER_STORE_BYTES)
                        .expect("verifier content identity"),
                ),
                ProtectedLauncherDescriptorRoleV1::BindingStore => Some(
                    protected_launcher_store_content_identity_v1(role, BINDING_STORE_BYTES)
                        .expect("binding content identity"),
                ),
                _ => None,
            },
        };
        descriptor.identity = protected_launcher_descriptor_v1_identity(&descriptor)
            .expect("protected descriptor identity");
        descriptor
    }

    fn capability_observation_challenge() -> ProtectedLauncherCapabilityObservationChallengeV1 {
        let nonce = [7_u8; 32];
        let mut challenge = ProtectedLauncherCapabilityObservationChallengeV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE.into(),
            identity: String::new(),
            workflow_run_id: "34153231585".into(),
            workflow_run_attempt: "1".into(),
            workflow_reference:
                "ota-run/ota/.github/workflows/secret-delivery-oidc-endpoint-evidence.yml@refs/heads/1.6.28-implementation"
                    .into(),
            nonce_commitment:
                protected_launcher_capability_observation_nonce_commitment_v1(&nonce)
                    .expect("nonce commitment"),
            issued_at_unix_seconds: 1_788_800_000,
            expires_at_unix_seconds: 1_788_800_300,
        };
        challenge.identity =
            protected_launcher_capability_observation_challenge_v1_identity(&challenge)
                .expect("challenge identity");
        challenge
    }

    fn capability_projection_verifier() -> ProtectedLauncherCapabilityProjectionVerifierV1 {
        let public_key = "A".repeat(43);
        let mut verifier = ProtectedLauncherCapabilityProjectionVerifierV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER.into(),
            identity: String::new(),
            key_identity: protected_launcher_capability_projection_key_identity_v1(&public_key)
                .expect("key identity"),
            public_key,
            key_usage: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_KEY_USAGE_V1.into(),
            signature_domain: std::str::from_utf8(
                PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1,
            )
            .expect("signature domain")
            .into(),
        };
        verifier.identity =
            protected_launcher_capability_projection_verifier_v1_identity(&verifier)
                .expect("verifier identity");
        verifier
    }

    fn capability_observation_projection() -> ProtectedLauncherCapabilityObservationProjectionV1 {
        let challenge = capability_observation_challenge();
        let verifier = capability_projection_verifier();
        let payload = ProtectedLauncherCapabilityObservationProjectionPayloadV1 {
            schema_version: 1,
            evidence_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION.into(),
            challenge_identity: challenge.identity,
            derivation: "verified".into(),
            target: ProtectedLauncherCapabilityObservationTargetV1 {
                environment: "self_hosted".into(),
                os: "linux".into(),
                architecture: "x64".into(),
            },
            capability_class: "systemd_protected_launcher_v3".into(),
            runner_version: "2.337.0".into(),
            signing_key_identity: verifier.key_identity,
        };
        ProtectedLauncherCapabilityObservationProjectionV1 {
            projection_identity: protected_launcher_capability_observation_projection_v1_identity(
                &payload,
            )
            .expect("projection identity"),
            payload,
            signature: "A".repeat(86),
        }
    }

    fn capability_observation_invocation() -> LauncherInvocationRequestV1 {
        LauncherInvocationRequestV1 {
            message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: "secret-delivery".into(),
            ota_arguments: vec!["run".into(), "publish".into()],
            repository_path: "/srv/ota/repository".into(),
        }
    }

    fn capability_observation_request() -> ProtectedLauncherCapabilityObservationRequestV1 {
        let nonce = [7_u8; 32];
        let invocation = capability_observation_invocation();
        let mut request = ProtectedLauncherCapabilityObservationRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST.into(),
            identity: String::new(),
            challenge: capability_observation_challenge(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            runner_version: "2.337.0".into(),
            expected_launcher_request_identity: launcher_invocation_request_identity(&invocation)
                .expect("invocation identity"),
        };
        request.identity = protected_launcher_capability_observation_request_v1_identity(&request)
            .expect("request identity");
        request
    }

    fn capability_observation_probe_request() -> ProtectedLauncherCapabilityObservationProbeRequestV1
    {
        let mut request = ProtectedLauncherCapabilityObservationProbeRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROBE_REQUEST.into(),
            identity: String::new(),
            invocation: capability_observation_invocation(),
            observation: capability_observation_request(),
        };
        request.identity =
            protected_launcher_capability_observation_probe_request_v1_identity(&request)
                .expect("probe request identity");
        request
    }

    fn capability_observation_signing_request()
    -> ProtectedLauncherCapabilityObservationSigningRequestV1 {
        let payload = capability_observation_projection().payload;
        let projection_identity =
            protected_launcher_capability_observation_projection_v1_identity(&payload)
                .expect("projection identity");
        let mut request = ProtectedLauncherCapabilityObservationSigningRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_REQUEST.into(),
            identity: String::new(),
            producer_binding_identity: format!("sha256:{}", "1".repeat(64)),
            verifier_identity: capability_projection_verifier().identity,
            protected_capability_identity: format!("sha256:{}", "2".repeat(64)),
            payload,
            projection_identity,
        };
        request.identity =
            protected_launcher_capability_observation_signing_request_v1_identity(&request)
                .expect("signing request identity");
        request
    }

    #[test]
    fn protected_launcher_authority_context_is_closed_and_domain_separated() {
        let context = protected_launcher_authority_context();
        assert_eq!(
            protected_launcher_authority_context_v1_identity(&context).as_deref(),
            Ok(context.identity.as_str())
        );
        assert_ne!(
            context.identity, context.runner_administrator.identity,
            "outer context identity must not alias administrator identity"
        );
        assert_ne!(
            context.identity, context.implementation_subject.identity,
            "outer context identity must not alias implementation identity"
        );

        let mut unknown_context = serde_json::to_value(&context).expect("context JSON");
        unknown_context
            .as_object_mut()
            .expect("context object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<ProtectedLauncherAuthorityContextV1>(unknown_context).is_err()
        );
        let mut unknown_administrator =
            serde_json::to_value(&context.runner_administrator).expect("administrator JSON");
        unknown_administrator
            .as_object_mut()
            .expect("administrator object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<RunnerAdministratorAuthorityV1>(unknown_administrator)
                .is_err()
        );
        let mut unknown_subject =
            serde_json::to_value(&context.implementation_subject).expect("subject JSON");
        unknown_subject
            .as_object_mut()
            .expect("subject object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<ProtectedLauncherImplementationSubjectV1>(unknown_subject)
                .is_err()
        );
        let mut unknown_target =
            serde_json::to_value(&context.implementation_subject.target).expect("target JSON");
        unknown_target
            .as_object_mut()
            .expect("target object")
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<ProtectedLauncherImplementationTargetV1>(unknown_target)
                .is_err()
        );

        let mut changed_administrator = context.clone();
        changed_administrator.runner_administrator.authority_id = "another-administrator".into();
        changed_administrator.runner_administrator.identity =
            runner_administrator_authority_v1_identity(&changed_administrator.runner_administrator)
                .expect("changed administrator identity");
        assert_ne!(
            protected_launcher_authority_context_v1_identity(&changed_administrator)
                .expect("changed context identity"),
            context.identity
        );

        let mut noncanonical_administrator = context.runner_administrator.clone();
        noncanonical_administrator.authority_id = "Runner-Administrator".into();
        assert_eq!(
            runner_administrator_authority_v1_identity(&noncanonical_administrator),
            Err(ProtocolError::InvalidRecord)
        );
        let mut changed_instance = context.clone();
        changed_instance.runner_administrator.authority_instance_id =
            URL_SAFE_NO_PAD.encode([2_u8; 32]);
        changed_instance.runner_administrator.identity =
            runner_administrator_authority_v1_identity(&changed_instance.runner_administrator)
                .expect("changed authority instance identity");
        assert_ne!(
            protected_launcher_authority_context_v1_identity(&changed_instance)
                .expect("changed authority context identity"),
            context.identity
        );
        for malformed_instance in [
            URL_SAFE_NO_PAD.encode([0_u8; 32]),
            URL_SAFE_NO_PAD.encode([1_u8; 31]),
            URL_SAFE_NO_PAD.encode([1_u8; 33]),
            format!("{}=", URL_SAFE_NO_PAD.encode([1_u8; 32])),
            format!("*{}", "A".repeat(42)),
            "B".repeat(43),
        ] {
            let mut malformed_authority = context.runner_administrator.clone();
            malformed_authority.authority_instance_id = malformed_instance;
            assert_eq!(
                runner_administrator_authority_v1_identity(&malformed_authority),
                Err(ProtocolError::InvalidRecord)
            );
        }

        let mut changed_subject = context.clone();
        changed_subject.implementation_subject.ota_artifact_identity =
            format!("sha256:{}", "9".repeat(64));
        changed_subject.implementation_subject.identity =
            protected_launcher_implementation_subject_v1_identity(
                &changed_subject.implementation_subject,
            )
            .expect("changed subject identity");
        assert_ne!(
            protected_launcher_authority_context_v1_identity(&changed_subject)
                .expect("changed context identity"),
            context.identity
        );

        let mut unsupported_target = context.implementation_subject.clone();
        unsupported_target.target.architecture = "aarch64".into();
        assert_eq!(
            protected_launcher_implementation_subject_v1_identity(&unsupported_target),
            Err(ProtocolError::InvalidRecord)
        );
        let mut invalid_revision = context.implementation_subject.clone();
        invalid_revision.protocol_source_revision = "0".repeat(40);
        assert_eq!(
            protected_launcher_implementation_subject_v1_identity(&invalid_revision),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn protected_launcher_dynamic_context_identities_are_exact() {
        let nonce = [7_u8; 32];
        assert_ne!(
            protected_launcher_invocation_nonce_v1_identity(&nonce)
                .expect("invocation nonce identity"),
            protected_launcher_capability_observation_nonce_commitment_v1(&nonce)
                .expect("public challenge nonce commitment")
        );
        assert_eq!(
            protected_launcher_invocation_nonce_v1_identity(&nonce[..31]),
            Err(ProtocolError::InvalidRecord)
        );

        let boot_id = "123e4567-e89b-12d3-a456-426614174000";
        assert!(protected_launcher_boot_v1_identity(boot_id).is_ok());
        for malformed in [
            "123E4567-e89b-12d3-a456-426614174000",
            "123e4567e89b12d3a456426614174000",
            "123e4567-e89b-12d3-a456-42661417400g",
            " 123e4567-e89b-12d3-a456-426614174000",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(
                protected_launcher_boot_v1_identity(malformed),
                Err(ProtocolError::InvalidRecord)
            );
        }
    }

    #[test]
    fn protected_capability_observation_records_are_closed_and_domain_separated() {
        let challenge = capability_observation_challenge();
        validate_protected_launcher_capability_observation_challenge_v1(
            &challenge,
            challenge.issued_at_unix_seconds,
        )
        .expect("fresh challenge");
        let projection = capability_observation_projection();
        validate_protected_launcher_capability_observation_projection_v1(&projection)
            .expect("projection structure");
        let verifier = capability_projection_verifier();
        validate_protected_launcher_capability_projection_verifier_v1(&verifier)
            .expect("verifier record");
        let request = capability_observation_request();
        assert_eq!(
            protected_launcher_capability_observation_request_v1_identity(&request)
                .expect("request identity"),
            request.identity
        );
        let probe_request = capability_observation_probe_request();
        assert_eq!(
            protected_launcher_capability_observation_probe_request_v1_identity(&probe_request)
                .expect("probe request identity"),
            probe_request.identity
        );
        validate_protected_launcher_capability_observation_response_v1(
            &ProtectedLauncherCapabilityObservationResponseV1 {
                schema_version: 1,
                message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_RESPONSE.into(),
                request_identity: request.identity.clone(),
                projection: projection.clone(),
            },
        )
        .expect("response structure");
        let signing_request = capability_observation_signing_request();
        validate_protected_launcher_capability_observation_signing_request_v1(&signing_request)
            .expect("signing request");
        let signing_response = ProtectedLauncherCapabilityObservationSigningResponseV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_RESPONSE.into(),
            request_identity: signing_request.identity.clone(),
            projection: projection.clone(),
        };
        validate_protected_launcher_capability_observation_signing_response_v1(&signing_response)
            .expect("signing response");
        reconcile_protected_launcher_capability_observation_signing_response_v1(
            &signing_request,
            &signing_response,
        )
        .expect("signing response reconciliation");

        assert_eq!(
            challenge.identity,
            "sha256:442b557b6066ad7a92e18065c5e743967ec75b76b3f341dcc29d573a65d2912c"
        );
        assert_eq!(
            projection.projection_identity,
            "sha256:baa4a23e06077b7c8d43c196ba5b45d4ba37faf8299f4a49fed939c545a7cd8e"
        );
        assert_eq!(
            verifier.key_identity,
            "sha256:82036a64e616d869ded1381fbf244f8ee8f6f3353839da23abbe8bf2688c78fc"
        );
        assert_eq!(
            verifier.identity,
            "sha256:9383e8b65bc0ed6ab5fcba4f70280793d28c9771003a2829d05af2b516ac4d86"
        );

        assert_ne!(challenge.identity, projection.projection_identity);
        assert_ne!(projection.projection_identity, verifier.identity);
        assert_ne!(verifier.identity, verifier.key_identity);
        let signature_message = protected_launcher_capability_observation_signature_message_v1(
            &projection.projection_identity,
        )
        .expect("signature message");
        assert!(
            signature_message
                .starts_with(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1)
        );
        assert_eq!(
            &signature_message
                [PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1.len()..],
            projection.projection_identity.as_bytes()
        );

        let projection_json = serde_json::to_string(&projection).expect("projection JSON");
        for prohibited in [
            "protected_launcher_capability_identity",
            "descriptor",
            "cgroup",
            "nonce_commitment",
            "repository_path",
            "provider",
            "credential",
        ] {
            assert!(!projection_json.contains(prohibited));
        }
        let mut unknown = serde_json::to_value(&projection).expect("projection value");
        unknown["capability_identity"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationProjectionV1>(unknown)
                .is_err()
        );
        let mut unknown_payload = serde_json::to_value(&projection.payload).expect("payload value");
        unknown_payload["provider"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationProjectionPayloadV1>(
                unknown_payload,
            )
            .is_err()
        );
        let mut unknown_target =
            serde_json::to_value(&projection.payload.target).expect("target value");
        unknown_target["region"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationTargetV1>(
                unknown_target
            )
            .is_err()
        );
        let mut unknown_challenge = serde_json::to_value(&challenge).expect("challenge value");
        unknown_challenge["nonce"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationChallengeV1>(
                unknown_challenge,
            )
            .is_err()
        );
        let mut unknown_request = serde_json::to_value(&request).expect("request value");
        unknown_request["provider"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationRequestV1>(
                unknown_request
            )
            .is_err()
        );
        let mut unknown_probe = serde_json::to_value(&probe_request).expect("probe value");
        unknown_probe["provider"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationProbeRequestV1>(
                unknown_probe
            )
            .is_err()
        );
        let mut unknown_verifier = serde_json::to_value(&verifier).expect("verifier value");
        unknown_verifier["alternate_key"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityProjectionVerifierV1>(
                unknown_verifier,
            )
            .is_err()
        );
        let mut unknown_signing_request =
            serde_json::to_value(&signing_request).expect("signing request value");
        unknown_signing_request["private_key"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationSigningRequestV1>(
                unknown_signing_request,
            )
            .is_err()
        );
        let mut unknown_signing_response =
            serde_json::to_value(&signing_response).expect("signing response value");
        unknown_signing_response["protected_capability_identity"] =
            serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityObservationSigningResponseV1>(
                unknown_signing_response,
            )
            .is_err()
        );
    }

    #[test]
    fn protected_capability_observation_substitutions_refuse() {
        let challenge = capability_observation_challenge();
        let request = capability_observation_request();
        let probe_request = capability_observation_probe_request();
        let signing_request = capability_observation_signing_request();
        for field in [
            "producer_binding_identity",
            "verifier_identity",
            "protected_capability_identity",
        ] {
            let mut changed = signing_request.clone();
            match field {
                "producer_binding_identity" => {
                    changed.producer_binding_identity = format!("sha256:{}", "a".repeat(64));
                }
                "verifier_identity" => {
                    changed.verifier_identity = format!("sha256:{}", "b".repeat(64));
                }
                "protected_capability_identity" => {
                    changed.protected_capability_identity = format!("sha256:{}", "c".repeat(64));
                }
                _ => unreachable!(),
            }
            assert_ne!(
                protected_launcher_capability_observation_signing_request_v1_identity(&changed)
                    .expect("changed signing identity"),
                signing_request.identity
            );
            assert_eq!(
                validate_protected_launcher_capability_observation_signing_request_v1(&changed),
                Err(ProtocolError::InvalidRecord)
            );
        }
        let mut changed_payload = signing_request.clone();
        changed_payload.payload.runner_version = "2.338.0".into();
        changed_payload.projection_identity =
            protected_launcher_capability_observation_projection_v1_identity(
                &changed_payload.payload,
            )
            .expect("changed projection identity");
        assert_ne!(
            protected_launcher_capability_observation_signing_request_v1_identity(&changed_payload)
                .expect("changed signing request identity"),
            signing_request.identity
        );
        assert_eq!(
            validate_protected_launcher_capability_observation_signing_request_v1(&changed_payload),
            Err(ProtocolError::InvalidRecord)
        );
        let original_response = ProtectedLauncherCapabilityObservationSigningResponseV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_RESPONSE.into(),
            request_identity: signing_request.identity.clone(),
            projection: ProtectedLauncherCapabilityObservationProjectionV1 {
                payload: signing_request.payload.clone(),
                projection_identity: signing_request.projection_identity.clone(),
                signature: "A".repeat(86),
            },
        };
        let mut substituted_response = original_response.clone();
        substituted_response.projection.payload.runner_version = "2.338.0".into();
        substituted_response.projection.projection_identity =
            protected_launcher_capability_observation_projection_v1_identity(
                &substituted_response.projection.payload,
            )
            .expect("substituted projection identity");
        validate_protected_launcher_capability_observation_signing_response_v1(
            &substituted_response,
        )
        .expect("self-consistent substituted response");
        assert_eq!(
            reconcile_protected_launcher_capability_observation_signing_response_v1(
                &signing_request,
                &substituted_response,
            ),
            Err(ProtocolError::InvalidRecord)
        );
        let mut substituted_request_identity = original_response;
        substituted_request_identity.request_identity = format!("sha256:{}", "d".repeat(64));
        assert_eq!(
            reconcile_protected_launcher_capability_observation_signing_response_v1(
                &signing_request,
                &substituted_request_identity,
            ),
            Err(ProtocolError::InvalidRecord)
        );
        for nonce in [
            "A".repeat(42),
            format!("{}=", "A".repeat(42)),
            "!".repeat(43),
        ] {
            let mut changed = request.clone();
            changed.nonce = nonce;
            assert_eq!(
                protected_launcher_capability_observation_request_v1_identity(&changed),
                Err(ProtocolError::InvalidRecord)
            );
        }
        let mut changed = request.clone();
        changed.runner_version = "banana".into();
        assert_eq!(
            protected_launcher_capability_observation_request_v1_identity(&changed),
            Err(ProtocolError::InvalidRecord)
        );
        let mut changed = request.clone();
        changed.expected_launcher_request_identity = format!("sha256:{}", "4".repeat(64));
        let changed_identity =
            protected_launcher_capability_observation_request_v1_identity(&changed)
                .expect("changed request identity");
        assert_ne!(changed_identity, request.identity);
        changed.identity = changed_identity;
        assert!(protected_launcher_capability_observation_request_v1_identity(&changed).is_ok());
        let mut malformed = request.clone();
        malformed.expected_launcher_request_identity = "not-an-identity".into();
        assert_eq!(
            protected_launcher_capability_observation_request_v1_identity(&malformed),
            Err(ProtocolError::InvalidRecord)
        );
        let mut substituted_probe = probe_request.clone();
        substituted_probe
            .observation
            .expected_launcher_request_identity = format!("sha256:{}", "f".repeat(64));
        substituted_probe.observation.identity =
            protected_launcher_capability_observation_request_v1_identity(
                &substituted_probe.observation,
            )
            .expect("substituted observation identity");
        assert_eq!(
            protected_launcher_capability_observation_probe_request_v1_identity(&substituted_probe),
            Err(ProtocolError::InvalidRecord)
        );
        assert_eq!(
            validate_protected_launcher_capability_observation_challenge_v1(
                &challenge,
                challenge.expires_at_unix_seconds + 1,
            ),
            Err(ProtocolError::InvalidRecord)
        );
        assert_eq!(
            validate_protected_launcher_capability_observation_challenge_v1(
                &challenge,
                challenge.issued_at_unix_seconds - 1,
            ),
            Err(ProtocolError::InvalidRecord)
        );
        for (issued_at_unix_seconds, expires_at_unix_seconds) in [
            (0, 1),
            (
                challenge.issued_at_unix_seconds,
                challenge.issued_at_unix_seconds,
            ),
            (
                challenge.expires_at_unix_seconds,
                challenge.issued_at_unix_seconds,
            ),
            (
                challenge.issued_at_unix_seconds,
                challenge.issued_at_unix_seconds + 301,
            ),
        ] {
            let mut changed = challenge.clone();
            changed.issued_at_unix_seconds = issued_at_unix_seconds;
            changed.expires_at_unix_seconds = expires_at_unix_seconds;
            assert_eq!(
                protected_launcher_capability_observation_challenge_v1_identity(&changed),
                Err(ProtocolError::InvalidRecord)
            );
        }
        for (run_id, attempt) in [("0", "1"), ("01", "1"), ("1", "0"), ("1", "01")] {
            let mut changed = challenge.clone();
            changed.workflow_run_id = run_id.into();
            changed.workflow_run_attempt = attempt.into();
            assert_eq!(
                protected_launcher_capability_observation_challenge_v1_identity(&changed),
                Err(ProtocolError::InvalidRecord)
            );
        }
        for workflow_reference in [
            "ota-run/ota/.github/workflows/.hidden.yml@refs/heads/main",
            "ota-run/ota/.github/workflows/check.yml@refs/heads/feature//test",
            "ota-run/ota/.github/workflows/check.yml@refs/heads/feature/../main",
            "ota-run/ota/.github/workflows/check.yml@refs/heads/feature/.hidden",
            "ota-run/ota/.github/workflows/check.yml@refs/heads/main^",
            "ota-run/ota/.github/workflows/check.yml@refs/heads/main.lock",
            "ota-run/ota/.github/workflows/nested/check.yml@refs/heads/main",
            "-ota/ota/.github/workflows/check.yml@refs/heads/main",
            "ota-/ota/.github/workflows/check.yml@refs/heads/main",
            "ota-run/.ota/.github/workflows/check.yml@refs/heads/main",
            "ota-run/ota/.github/workflows/check.yml@main",
        ] {
            let mut changed = challenge.clone();
            changed.workflow_reference = workflow_reference.into();
            assert_eq!(
                protected_launcher_capability_observation_challenge_v1_identity(&changed),
                Err(ProtocolError::InvalidRecord)
            );
        }

        let projection = capability_observation_projection();
        let mut changed = projection.clone();
        changed.payload.challenge_identity = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            validate_protected_launcher_capability_observation_projection_v1(&changed),
            Err(ProtocolError::InvalidRecord)
        );
        let mut changed = projection.clone();
        changed.payload.target.architecture = "arm64".into();
        assert_eq!(
            protected_launcher_capability_observation_projection_v1_identity(&changed.payload),
            Err(ProtocolError::InvalidRecord)
        );
        assert_eq!(
            validate_protected_launcher_capability_observation_projection_v1(&changed),
            Err(ProtocolError::InvalidRecord)
        );

        for runner_version in ["2.337.0", "2.337.0-rc.1", "2.337.0+build.7"] {
            let mut changed = projection.clone();
            changed.payload.runner_version = runner_version.into();
            changed.projection_identity =
                protected_launcher_capability_observation_projection_v1_identity(&changed.payload)
                    .expect("canonical runner version");
            validate_protected_launcher_capability_observation_projection_v1(&changed)
                .expect("canonical projection");
        }
        for runner_version in ["banana", "01.2", "2.337", "v2.337.0", "2.337.0-01"] {
            let mut changed = projection.clone();
            changed.payload.runner_version = runner_version.into();
            assert_eq!(
                protected_launcher_capability_observation_projection_v1_identity(&changed.payload),
                Err(ProtocolError::InvalidRecord)
            );
        }

        for (field, value) in [
            ("challenge_identity", format!("sha256:{}", "b".repeat(64))),
            ("runner_version", "2.338.0".into()),
            ("signing_key_identity", format!("sha256:{}", "c".repeat(64))),
        ] {
            let mut changed = projection.clone();
            match field {
                "challenge_identity" => changed.payload.challenge_identity = value,
                "runner_version" => changed.payload.runner_version = value,
                "signing_key_identity" => changed.payload.signing_key_identity = value,
                _ => unreachable!(),
            }
            let changed_identity =
                protected_launcher_capability_observation_projection_v1_identity(&changed.payload)
                    .expect("structurally valid substitution");
            assert_ne!(
                changed_identity, projection.projection_identity,
                "{field} is bound"
            );
        }

        let verifier = capability_projection_verifier();
        let mut noncanonical_key = verifier.clone();
        noncanonical_key.public_key = format!("{}B", "A".repeat(42));
        assert_eq!(
            protected_launcher_capability_projection_verifier_v1_identity(&noncanonical_key),
            Err(ProtocolError::InvalidRecord)
        );
        for final_character in [
            b'A', b'E', b'I', b'M', b'Q', b'U', b'Y', b'c', b'g', b'k', b'o', b's', b'w', b'0',
            b'4', b'8',
        ] {
            let mut accepted = verifier.clone();
            accepted.public_key = format!("{}{}", "A".repeat(42), char::from(final_character));
            accepted.key_identity =
                protected_launcher_capability_projection_key_identity_v1(&accepted.public_key)
                    .expect("canonical public-key tail");
            accepted.identity =
                protected_launcher_capability_projection_verifier_v1_identity(&accepted)
                    .expect("canonical verifier tail");
            validate_protected_launcher_capability_projection_verifier_v1(&accepted)
                .expect("canonical verifier");
        }
        for public_key in [
            format!("{}=", "A".repeat(42)),
            "A".repeat(42),
            format!("{}!", "A".repeat(42)),
        ] {
            assert_eq!(
                protected_launcher_capability_projection_key_identity_v1(&public_key),
                Err(ProtocolError::InvalidRecord)
            );
        }
        let mut noncanonical_signature = projection;
        noncanonical_signature.signature = format!("{}B", "A".repeat(85));
        assert_eq!(
            validate_protected_launcher_capability_observation_projection_v1(
                &noncanonical_signature,
            ),
            Err(ProtocolError::InvalidRecord)
        );
        for final_character in [b'A', b'Q', b'g', b'w'] {
            let mut accepted = capability_observation_projection();
            accepted.signature = format!("{}{}", "A".repeat(85), char::from(final_character));
            validate_protected_launcher_capability_observation_projection_v1(&accepted)
                .expect("canonical signature tail");
        }
        for field in [
            "schema_version",
            "record_kind",
            "key_usage",
            "signature_domain",
        ] {
            let mut value = serde_json::to_value(&verifier).expect("verifier value");
            value[field] = match field {
                "schema_version" => serde_json::json!(2),
                _ => serde_json::json!("substituted"),
            };
            let changed: ProtectedLauncherCapabilityProjectionVerifierV1 =
                serde_json::from_value(value).expect("changed verifier");
            assert_eq!(
                protected_launcher_capability_projection_verifier_v1_identity(&changed),
                Err(ProtocolError::InvalidRecord),
                "{field} substitution must refuse"
            );
        }
    }

    fn protected_capability() -> ProtectedLauncherCapabilityV1 {
        let identity = |value: char| format!("sha256:{}", value.to_string().repeat(64));
        let descriptors = vec![
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket, 1),
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::VerifierStore, 2),
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::BindingStore, 3),
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::InvocationCgroup, 4),
        ];
        let mut capability = ProtectedLauncherCapabilityV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: PROTECTED_LAUNCHER_CAPABILITY.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            launcher_request_identity: identity('1'),
            launcher_executable_identity: identity('2'),
            launcher_configuration_identity: identity('3'),
            launcher_service_binding_identity: identity('4'),
            launcher_profile_identity: identity('5'),
            runner_administrator_identity: identity('6'),
            service_uid: 0,
            service_gid: 0,
            invocation_nonce_identity: identity('7'),
            boot_identity: identity('8'),
            protected_launcher_instance_identity: identity('9'),
            systemd_invocation_identity: identity('a'),
            systemd_scope_identity: identity('b'),
            cgroup_identity: identity('0'),
            child_process_identity: identity('c'),
            principal_mapping_identity: identity('d'),
            process_posture_identity: identity('e'),
            implementation_subject_identity: identity('f'),
            descriptors,
        };
        capability.identity = protected_launcher_capability_v1_identity(&capability)
            .expect("protected launcher capability identity");
        capability
    }

    #[test]
    fn framing_is_bounded_and_exact() {
        let payload = br#"{"message_kind":"challenge_request"}"#;
        let frame = encode_frame(payload).expect("frame");
        assert_eq!(decode_frame(&frame).expect("payload"), payload);
        assert_eq!(
            encode_frame(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(ProtocolError::FrameTooLarge)
        );
        assert_eq!(
            decode_frame(&[0, 0, 0, 2, b'{']),
            Err(ProtocolError::IncompleteFrame)
        );
    }

    #[test]
    fn protected_launcher_capability_is_closed_canonical_and_content_addressed() {
        let capability = protected_capability();
        assert_eq!(
            sha256_identity(
                &serde_jcs::to_vec(&capability.descriptors[0]).expect("descriptor JCS")
            ),
            "sha256:a2a4518f22a1ce63ea8c9520b963fa9d54a6f92bab458d27d8a40cb7ef776a1e"
        );
        assert_eq!(
            sha256_identity(&serde_jcs::to_vec(&capability).expect("capability JCS")),
            "sha256:d4489737bb58897aad5c42525cb3f7a3dc7e68caae6622860d27b3dfb8c0705c"
        );
        assert_eq!(
            capability.descriptors[0].identity,
            "sha256:7a9488e0effeb2b791c2ad184d8f94e4b6644f6fb3fee648dcd9423a701ff3a7"
        );
        assert_eq!(
            capability.identity,
            "sha256:a261408212f7f0da88b1ae529c7b16f55c2dd8cf9baf71480d85e516c60fdad0"
        );
        let descriptor_json =
            serde_json::to_value(&capability.descriptors[0]).expect("descriptor JSON");
        assert_eq!(descriptor_json["role"], "launcher_session_socket");
        assert_eq!(descriptor_json["kind"], "unix_stream_socket");
        assert_eq!(descriptor_json["access"], "read_write");
        assert!(descriptor_json.get("content_identity").is_none());
        assert_eq!(
            protected_launcher_store_content_identity_v1(
                ProtectedLauncherDescriptorRoleV1::VerifierStore,
                VERIFIER_STORE_BYTES,
            )
            .expect("verifier store identity"),
            "sha256:e56e26fb0be37f27cdc15d0fc10a682a3a7492cf4e1c8bb04481bcb8b9db9b85"
        );
        assert_eq!(
            protected_launcher_store_content_identity_v1(
                ProtectedLauncherDescriptorRoleV1::BindingStore,
                BINDING_STORE_BYTES,
            )
            .expect("binding store identity"),
            "sha256:c89a3a030fa0549e6df7ba28e7a475efdbd155fcc601ea6357dae83a2d8613c8"
        );
        assert_eq!(
            protected_launcher_capability_v1_identity(&capability)
                .expect("stable capability identity"),
            capability.identity
        );

        let mut reordered = capability.clone();
        reordered.descriptors.reverse();
        assert_eq!(
            protected_launcher_capability_v1_identity(&reordered)
                .expect("descriptor order is not semantic"),
            capability.identity
        );

        let mut changed_store = capability.clone();
        let verifier = changed_store
            .descriptors
            .iter_mut()
            .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::VerifierStore)
            .expect("verifier descriptor");
        verifier.size += 1;
        verifier.identity = protected_launcher_descriptor_v1_identity(verifier)
            .expect("changed verifier descriptor identity");
        assert_ne!(
            protected_launcher_capability_v1_identity(&changed_store)
                .expect("changed store capability identity"),
            capability.identity
        );

        let mut changed_request = capability.clone();
        changed_request.launcher_request_identity = format!("sha256:{}", "0".repeat(64));
        assert_ne!(
            protected_launcher_capability_v1_identity(&changed_request)
                .expect("changed request capability identity"),
            capability.identity
        );

        let mut changed_subject = capability.clone();
        changed_subject.implementation_subject_identity = format!("sha256:{}", "0".repeat(64));
        assert_ne!(
            protected_launcher_capability_v1_identity(&changed_subject)
                .expect("changed subject capability identity"),
            capability.identity
        );

        let mut duplicate = capability.clone();
        duplicate.descriptors[2] = duplicate.descriptors[1].clone();
        assert_eq!(
            protected_launcher_capability_v1_identity(&duplicate),
            Err(ProtocolError::InvalidRecord)
        );

        let mut missing = capability.clone();
        missing.descriptors.pop();
        assert_eq!(
            protected_launcher_capability_v1_identity(&missing),
            Err(ProtocolError::InvalidRecord)
        );

        let mut unknown_capability_field =
            serde_json::to_value(&capability).expect("capability JSON");
        unknown_capability_field["provider_token"] = serde_json::Value::String("forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherCapabilityV1>(unknown_capability_field)
                .is_err()
        );
        let mut unknown_descriptor_field =
            serde_json::to_value(&capability.descriptors[0]).expect("descriptor JSON");
        unknown_descriptor_field["path"] = serde_json::Value::String("/forbidden".into());
        assert!(
            serde_json::from_value::<ProtectedLauncherDescriptorV1>(unknown_descriptor_field)
                .is_err()
        );

        let mut wrong_cgroup = capability.clone();
        wrong_cgroup.cgroup_identity = format!("sha256:{}", "1".repeat(64));
        assert_ne!(
            protected_launcher_capability_v1_identity(&wrong_cgroup)
                .expect("changed cgroup identity remains structurally valid"),
            capability.identity
        );

        let mut non_root_service = capability.clone();
        non_root_service.service_uid = 1000;
        assert_eq!(
            protected_launcher_capability_v1_identity(&non_root_service),
            Err(ProtocolError::InvalidRecord)
        );

        let mut writable_store = capability;
        let binding = writable_store
            .descriptors
            .iter_mut()
            .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::BindingStore)
            .expect("binding descriptor");
        binding.access = ProtectedLauncherDescriptorAccessV1::ReadWrite;
        assert_eq!(
            protected_launcher_descriptor_v1_identity(binding),
            Err(ProtocolError::InvalidRecord)
        );
        assert_eq!(
            protected_launcher_capability_v1_identity(&writable_store),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn protected_launcher_capability_binds_every_private_identity_without_secret_material() {
        let capability = protected_capability();
        let original_identity = capability.identity.clone();
        let substituted_identity = format!("sha256:{}", "0".repeat(64));
        for field in [
            "launcher_request_identity",
            "launcher_executable_identity",
            "launcher_configuration_identity",
            "launcher_service_binding_identity",
            "launcher_profile_identity",
            "runner_administrator_identity",
            "invocation_nonce_identity",
            "boot_identity",
            "protected_launcher_instance_identity",
            "systemd_invocation_identity",
            "systemd_scope_identity",
            "child_process_identity",
            "principal_mapping_identity",
            "process_posture_identity",
            "implementation_subject_identity",
        ] {
            let mut value = serde_json::to_value(&capability).expect("capability JSON");
            value[field] = serde_json::Value::String(substituted_identity.clone());
            let changed: ProtectedLauncherCapabilityV1 =
                serde_json::from_value(value).expect("changed capability");
            assert_ne!(
                protected_launcher_capability_v1_identity(&changed)
                    .expect("changed capability identity"),
                original_identity,
                "{field} must participate in capability identity"
            );
        }

        let mut changed_cgroup = capability.clone();
        let cgroup = changed_cgroup
            .descriptors
            .iter_mut()
            .find(|descriptor| {
                descriptor.role == ProtectedLauncherDescriptorRoleV1::InvocationCgroup
            })
            .expect("cgroup descriptor");
        cgroup.inode += 1;
        cgroup.identity = protected_launcher_descriptor_v1_identity(cgroup)
            .expect("changed cgroup descriptor identity");
        changed_cgroup.cgroup_identity = substituted_identity;
        assert_ne!(
            protected_launcher_capability_v1_identity(&changed_cgroup)
                .expect("changed cgroup capability identity"),
            original_identity
        );

        let value = serde_json::to_value(&capability).expect("capability JSON");
        let keys = value
            .as_object()
            .expect("capability object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "boot_identity",
                "cgroup_identity",
                "child_process_identity",
                "descriptors",
                "identity",
                "implementation_subject_identity",
                "invocation_nonce_identity",
                "launcher_configuration_identity",
                "launcher_executable_identity",
                "launcher_profile_identity",
                "launcher_request_identity",
                "launcher_service_binding_identity",
                "message_kind",
                "principal_mapping_identity",
                "process_posture_identity",
                "protected_launcher_instance_identity",
                "protocol_version",
                "runner_administrator_identity",
                "schema_version",
                "service_gid",
                "service_uid",
                "systemd_invocation_identity",
                "systemd_scope_identity",
            ])
        );
        let descriptor_keys = value["descriptors"]
            .as_array()
            .expect("descriptor array")
            .iter()
            .flat_map(|descriptor| {
                descriptor
                    .as_object()
                    .expect("descriptor object")
                    .keys()
                    .map(String::as_str)
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            descriptor_keys,
            std::collections::BTreeSet::from([
                "access",
                "content_identity",
                "device",
                "identity",
                "inode",
                "kind",
                "mode",
                "owner_gid",
                "owner_uid",
                "role",
                "schema_version",
                "size",
            ])
        );
        let encoded = serde_json::to_vec(&value).expect("capability bytes");
        encode_frame(&encoded).expect("bounded capability frame");
        let encoded = String::from_utf8(encoded).expect("capability JSON is UTF-8");
        for prohibited in [
            "token",
            "provider",
            "secret",
            "path",
            "credential",
            "handle",
            "verifiers",
            "bindings",
        ] {
            assert!(
                !encoded.contains(prohibited),
                "capability must not carry {prohibited} material"
            );
        }
    }

    #[test]
    fn protected_launcher_capability_reconciles_canonical_launcher_evidence() {
        let identity = |value: char| format!("sha256:{}", value.to_string().repeat(64));
        let principal = |uid: u32, gid: u32| UnixPrincipalIdentity {
            real_uid: uid,
            effective_uid: uid,
            saved_uid: uid,
            filesystem_uid: uid,
            real_gid: gid,
            effective_gid: gid,
            saved_gid: gid,
            filesystem_gid: gid,
        };
        let request = LauncherInvocationRequestV1 {
            message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: "secret-delivery".into(),
            ota_arguments: vec!["run".into(), "publish".into()],
            repository_path: "/srv/ota/repository".into(),
        };
        let request_identity =
            launcher_invocation_request_identity(&request).expect("launcher request identity");
        let launcher_configuration_identity = identity('3');
        let job_profile = systemd_job_principal_profile_v2();
        let job_profile_identity =
            systemd_job_principal_profile_identity(&job_profile).expect("job profile identity");
        let mut principal_mapping = LauncherPrincipalMappingV1 {
            schema_version: 1,
            identity: String::new(),
            job_peer: principal(1001, 1001),
            execution: principal(1002, 1002),
            job_principal_profile_identity: job_profile_identity.clone(),
            launcher_session_binding_identity: launcher_configuration_identity.clone(),
        };
        principal_mapping.identity = launcher_principal_mapping_identity(&principal_mapping)
            .expect("principal mapping identity");
        let mut working_directory = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: request.repository_path.clone(),
            device: 31,
            inode: 3100,
        };
        working_directory.identity = launcher_working_directory_identity(&working_directory)
            .expect("working-directory identity");
        let mut child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: "secret-delivery-1".into(),
            request_identity: request_identity.clone(),
            pid: 4242,
            process_start_time_identity: identity('7'),
            ota_binary_identity: identity('2'),
            principal_mapping_identity: principal_mapping.identity.clone(),
            working_directory_identity: working_directory.identity,
        };
        child.identity = launcher_child_process_identity(&child).expect("child identity");
        let mut scope = LauncherSystemdScopeV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: child.invocation_id.clone(),
            request_identity: request_identity.clone(),
            child_identity: child.identity.clone(),
            child_pid: child.pid,
            unit_name: "ota-authority-invocation-0123456789abcdef.scope".into(),
            unit_object_path:
                "/org/freedesktop/systemd1/unit/ota_2dauthority_2dinvocation_2d0123456789abcdef_2escope"
                    .into(),
            slice: "ota-authority-invocations.slice".into(),
            control_group: "/ota-authority-invocations.slice/ota-authority-invocation-0123456789abcdef.scope"
                .into(),
            delegate: false,
            kill_mode: "control-group".into(),
            collect_mode: "inactive-or-failed".into(),
        };
        scope.identity = launcher_systemd_scope_identity(&scope).expect("scope identity");
        let mut process_posture = OtaProcessPostureV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: OTA_PROCESS_POSTURE.into(),
            pid: child.pid,
            process_start_time_identity: child.process_start_time_identity.clone(),
            ota_binary_identity: child.ota_binary_identity.clone(),
            no_new_privs: true,
            dumpable: 0,
            ptracer_clear_applied: true,
            principal_mapping_identity: principal_mapping.identity.clone(),
        };
        process_posture.identity =
            ota_process_posture_identity(&process_posture).expect("process posture identity");
        let launcher_profile = systemd_launcher_profile_v3();
        let launcher_profile_identity = systemd_launcher_profile_identity(&launcher_profile)
            .expect("launcher profile identity");
        let mut foundation = SystemdProtectedLauncherInstanceEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            principal_mapping: principal_mapping.clone(),
            process_posture: process_posture.clone(),
            systemd_launcher_profile_identity: launcher_profile_identity.clone(),
            systemd_job_principal_profile_identity: job_profile_identity,
            launcher_session_binding_identity: launcher_configuration_identity.clone(),
            systemd_invocation_identity: scope.identity.clone(),
            working_directory_identity: child.working_directory_identity.clone(),
            child_process_identity: child.identity.clone(),
        };
        foundation.identity =
            systemd_protected_launcher_instance_v3_foundation_identity(&foundation)
                .expect("launcher foundation identity");
        let mut launcher_instance = SystemdProtectedLauncherInstanceEvidenceV2 {
            schema_version: 3,
            identity: String::new(),
            instance_v1: foundation,
            launcher_observations: launcher_profile
                .evidence_sources
                .into_iter()
                .map(|source| SystemdLauncherObservation {
                    source,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: "verified_by_systemd_protected_launcher".into(),
                    evidence_identity: Some(identity('8')),
                })
                .collect(),
            job_principal_observations: job_profile
                .requirements
                .into_iter()
                .map(|required| SystemdJobPrincipalObservation {
                    requirement: required.requirement,
                    evidence_methods: required.evidence_methods,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: "verified_by_systemd_protected_launcher".into(),
                    evidence_identity: Some(identity('9')),
                })
                .collect(),
        };
        launcher_instance.identity =
            systemd_protected_launcher_instance_v2_identity(&launcher_instance)
                .expect("complete launcher instance identity");

        let descriptors = vec![
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket, 1),
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::VerifierStore, 2),
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::BindingStore, 3),
            protected_descriptor(ProtectedLauncherDescriptorRoleV1::InvocationCgroup, 4),
        ];
        let cgroup_descriptor = &descriptors[3];
        let cgroup_identity = protected_launcher_cgroup_v1_identity(&scope, cgroup_descriptor)
            .expect("cgroup identity");
        assert_eq!(
            cgroup_identity,
            "sha256:6a970aa7da9df5e80123b75ff98418340b0ab3d21983a8068f22502c0ed99a89"
        );
        let runner_administrator_identity = identity('6');
        let invocation_nonce_identity = identity('a');
        let boot_identity = identity('b');
        let implementation_subject_identity = identity('c');
        let launcher_service_binding_identity = identity('4');
        let mut capability = ProtectedLauncherCapabilityV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: PROTECTED_LAUNCHER_CAPABILITY.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            launcher_request_identity: request_identity,
            launcher_executable_identity: child.ota_binary_identity.clone(),
            launcher_configuration_identity: launcher_configuration_identity.clone(),
            launcher_service_binding_identity: launcher_service_binding_identity.clone(),
            launcher_profile_identity: launcher_profile_identity.clone(),
            runner_administrator_identity: runner_administrator_identity.clone(),
            service_uid: 0,
            service_gid: 0,
            invocation_nonce_identity: invocation_nonce_identity.clone(),
            boot_identity: boot_identity.clone(),
            protected_launcher_instance_identity: launcher_instance.identity.clone(),
            systemd_invocation_identity: scope.identity.clone(),
            systemd_scope_identity: scope.identity.clone(),
            cgroup_identity,
            child_process_identity: child.identity.clone(),
            principal_mapping_identity: principal_mapping.identity.clone(),
            process_posture_identity: process_posture.identity.clone(),
            implementation_subject_identity: implementation_subject_identity.clone(),
            descriptors: descriptors.clone(),
        };
        capability.identity =
            protected_launcher_capability_v1_identity(&capability).expect("capability identity");
        let evidence = ProtectedLauncherCapabilityEvidenceV1 {
            request: &request,
            child: &child,
            scope: &scope,
            principal_mapping: &principal_mapping,
            process_posture: &process_posture,
            launcher_instance: &launcher_instance,
            launcher_executable_identity: child.ota_binary_identity.as_str(),
            launcher_configuration_identity: launcher_configuration_identity.as_str(),
            launcher_service_binding_identity: launcher_service_binding_identity.as_str(),
            launcher_profile_identity: launcher_profile_identity.as_str(),
            runner_administrator_identity: runner_administrator_identity.as_str(),
            service_uid: 0,
            service_gid: 0,
            invocation_nonce_identity: invocation_nonce_identity.as_str(),
            boot_identity: boot_identity.as_str(),
            implementation_subject_identity: implementation_subject_identity.as_str(),
            observed_descriptors: descriptors.as_slice(),
            verifier_store_bytes: VERIFIER_STORE_BYTES,
            binding_store_bytes: BINDING_STORE_BYTES,
        };
        assert_eq!(
            validate_protected_launcher_capability_v1(&capability, &evidence),
            Ok(())
        );

        let mut forged_child = child.clone();
        forged_child.principal_mapping_identity = identity('0');
        forged_child.identity =
            launcher_child_process_identity(&forged_child).expect("forged child identity");
        let mut forged_scope = scope.clone();
        forged_scope.child_identity = forged_child.identity.clone();
        forged_scope.identity =
            launcher_systemd_scope_identity(&forged_scope).expect("forged scope identity");
        let mut forged_instance = launcher_instance.clone();
        forged_instance.instance_v1.child_process_identity = forged_child.identity.clone();
        forged_instance.instance_v1.systemd_invocation_identity = forged_scope.identity.clone();
        forged_instance.instance_v1.identity =
            systemd_protected_launcher_instance_v3_foundation_identity(
                &forged_instance.instance_v1,
            )
            .expect("forged launcher foundation identity");
        forged_instance.identity =
            systemd_protected_launcher_instance_v2_identity(&forged_instance)
                .expect("forged launcher instance identity");
        let mut forged_mapping_capability = capability.clone();
        forged_mapping_capability.child_process_identity = forged_child.identity.clone();
        forged_mapping_capability.systemd_invocation_identity = forged_scope.identity.clone();
        forged_mapping_capability.systemd_scope_identity = forged_scope.identity.clone();
        forged_mapping_capability.cgroup_identity =
            protected_launcher_cgroup_v1_identity(&forged_scope, cgroup_descriptor)
                .expect("forged cgroup identity");
        forged_mapping_capability.protected_launcher_instance_identity =
            forged_instance.identity.clone();
        forged_mapping_capability.identity =
            protected_launcher_capability_v1_identity(&forged_mapping_capability)
                .expect("self-consistent forged capability identity");
        let forged_mapping_evidence = ProtectedLauncherCapabilityEvidenceV1 {
            child: &forged_child,
            scope: &forged_scope,
            launcher_instance: &forged_instance,
            ..evidence
        };
        assert_eq!(
            validate_protected_launcher_capability_v1(
                &forged_mapping_capability,
                &forged_mapping_evidence,
            ),
            Err(ProtocolError::InvalidRecord)
        );

        let mut substituted_cgroup = capability.clone();
        substituted_cgroup.cgroup_identity = identity('d');
        substituted_cgroup.identity =
            protected_launcher_capability_v1_identity(&substituted_cgroup)
                .expect("self-consistent substituted capability");
        assert_eq!(
            validate_protected_launcher_capability_v1(&substituted_cgroup, &evidence),
            Err(ProtocolError::InvalidRecord)
        );

        let mut swapped_stores = capability.clone();
        let verifier_index = swapped_stores
            .descriptors
            .iter()
            .position(|descriptor| {
                descriptor.role == ProtectedLauncherDescriptorRoleV1::VerifierStore
            })
            .expect("verifier descriptor");
        let binding_index = swapped_stores
            .descriptors
            .iter()
            .position(|descriptor| {
                descriptor.role == ProtectedLauncherDescriptorRoleV1::BindingStore
            })
            .expect("binding descriptor");
        swapped_stores.descriptors[verifier_index].role =
            ProtectedLauncherDescriptorRoleV1::BindingStore;
        swapped_stores.descriptors[binding_index].role =
            ProtectedLauncherDescriptorRoleV1::VerifierStore;
        for descriptor in &mut swapped_stores.descriptors {
            descriptor.identity = protected_launcher_descriptor_v1_identity(descriptor)
                .expect("self-consistent swapped descriptor");
        }
        swapped_stores.identity = protected_launcher_capability_v1_identity(&swapped_stores)
            .expect("self-consistent swapped capability");
        assert_eq!(
            validate_protected_launcher_capability_v1(&swapped_stores, &evidence),
            Err(ProtocolError::InvalidRecord)
        );

        let cgroup = capability
            .descriptors
            .iter()
            .find(|descriptor| {
                descriptor.role == ProtectedLauncherDescriptorRoleV1::InvocationCgroup
            })
            .expect("cgroup descriptor")
            .clone();
        let mut writable_cgroup = cgroup;
        writable_cgroup.mode = 0o777;
        assert_eq!(
            protected_launcher_descriptor_v1_identity(&writable_cgroup),
            Err(ProtocolError::InvalidRecord)
        );

        let mut aliased_stores = capability;
        let verifier = aliased_stores
            .descriptors
            .iter()
            .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::VerifierStore)
            .expect("verifier descriptor")
            .clone();
        let binding = aliased_stores
            .descriptors
            .iter_mut()
            .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::BindingStore)
            .expect("binding descriptor");
        binding.device = verifier.device;
        binding.inode = verifier.inode;
        binding.identity = protected_launcher_descriptor_v1_identity(binding)
            .expect("aliased descriptor identity");
        assert_eq!(
            protected_launcher_capability_v1_identity(&aliased_stores),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn systemd_launcher_request_is_bounded_and_untrusted() {
        let request = LauncherInvocationRequestV1 {
            message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: "production-release".into(),
            ota_arguments: vec!["up".into(), "--workflow".into(), "release".into()],
            repository_path: "/srv/build/repository".into(),
        };
        assert_eq!(validate_launcher_invocation_request_v1(&request), Ok(()));

        let mut relative_path = request.clone();
        relative_path.repository_path = "repository".into();
        assert_eq!(
            validate_launcher_invocation_request_v1(&relative_path),
            Err(ProtocolError::InvalidRecord)
        );

        let mut parent_path = request.clone();
        parent_path.repository_path = "/srv/build/../repository".into();
        assert_eq!(
            validate_launcher_invocation_request_v1(&parent_path),
            Err(ProtocolError::InvalidRecord)
        );

        let mut unknown = serde_json::to_value(&request).expect("request JSON");
        unknown["caller_identity"] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<LauncherInvocationRequestV1>(unknown).is_err());
    }

    #[test]
    fn launcher_boundary_identities_bind_request_directory_and_child() {
        let request = LauncherInvocationRequestV1 {
            message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: "production-release".into(),
            ota_arguments: vec!["run".into(), "publish".into()],
            repository_path: "/srv/build/repository".into(),
        };
        let request_identity =
            launcher_invocation_request_identity(&request).expect("request identity");
        assert_eq!(
            request_identity,
            "sha256:4201f144c980632196b2edb0443833559f3903cdc498807d16e54569ae9d0ab4"
        );
        assert_eq!(
            serde_json::to_value(&request).expect("request JSON"),
            serde_json::json!({
                "message_kind": "launcher_invocation_request",
                "protocol_version": "ota-authority-launcher/systemd/v1",
                "authority_id": "production-release",
                "ota_arguments": ["run", "publish"],
                "repository_path": "/srv/build/repository"
            })
        );
        let mut changed_request = request.clone();
        changed_request.ota_arguments[1] = "verify".into();
        assert_ne!(
            launcher_invocation_request_identity(&changed_request).expect("changed request"),
            request_identity
        );

        let mut directory = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: request.repository_path,
            device: 8,
            inode: 42,
        };
        directory.identity =
            launcher_working_directory_identity(&directory).expect("working directory identity");
        assert_eq!(
            directory.identity,
            "sha256:ca936d9590192ddb060764e59e84c3f96149f3fad79bfc4c3140b444bf3d86bc"
        );
        assert_eq!(
            serde_json::to_value(&directory).expect("directory JSON"),
            serde_json::json!({
                "schema_version": 1,
                "identity": directory.identity.clone(),
                "logical_path": "/srv/build/repository",
                "device": 8,
                "inode": 42
            })
        );
        assert_eq!(
            launcher_working_directory_identity(&directory).expect("stable directory identity"),
            directory.identity
        );
        let mut changed_directory = directory.clone();
        changed_directory.inode += 1;
        assert_ne!(
            launcher_working_directory_identity(&changed_directory)
                .expect("changed directory identity"),
            directory.identity
        );
        let mut invalid_directory = directory.clone();
        invalid_directory.logical_path = "/srv/build/../escape".into();
        assert_eq!(
            launcher_working_directory_identity(&invalid_directory),
            Err(ProtocolError::InvalidRecord)
        );

        let identity = |character: char| format!("sha256:{}", character.to_string().repeat(64));
        let mut child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: "invocation-123".into(),
            request_identity,
            pid: 4242,
            process_start_time_identity: identity('a'),
            ota_binary_identity: identity('b'),
            principal_mapping_identity: identity('c'),
            working_directory_identity: directory.identity,
        };
        child.identity = launcher_child_process_identity(&child).expect("child identity");
        assert_eq!(
            child.identity,
            "sha256:32a19d003ac5758bc91bc5d818e8f1906f347e7665ac202148848a5cd86f2616"
        );
        assert_eq!(
            serde_json::to_value(&child).expect("child JSON"),
            serde_json::json!({
                "schema_version": 1,
                "identity": child.identity.clone(),
                "invocation_id": "invocation-123",
                "request_identity": "sha256:4201f144c980632196b2edb0443833559f3903cdc498807d16e54569ae9d0ab4",
                "pid": 4242,
                "process_start_time_identity": identity('a'),
                "ota_binary_identity": identity('b'),
                "principal_mapping_identity": identity('c'),
                "working_directory_identity": "sha256:ca936d9590192ddb060764e59e84c3f96149f3fad79bfc4c3140b444bf3d86bc"
            })
        );
        assert_eq!(
            launcher_child_process_identity(&child).expect("stable child identity"),
            child.identity
        );
        let mut changed_child = child.clone();
        changed_child.pid += 1;
        assert_ne!(
            launcher_child_process_identity(&changed_child).expect("changed child identity"),
            child.identity
        );
        let mut changed_request_binding = child.clone();
        changed_request_binding.request_identity = identity('d');
        assert_ne!(
            launcher_child_process_identity(&changed_request_binding)
                .expect("changed request binding"),
            child.identity
        );
        let mut continuation = LauncherStartupContinuationV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_STARTUP_CONTINUATION.into(),
            invocation_id: child.invocation_id.clone(),
            child_process_identity: child.identity.clone(),
            working_directory_identity: child.working_directory_identity.clone(),
            process_posture_identity: identity('e'),
            principal_mapping_identity: child.principal_mapping_identity.clone(),
        };
        continuation.identity =
            launcher_startup_continuation_identity(&continuation).expect("continuation identity");
        assert_eq!(
            launcher_startup_continuation_identity(&continuation)
                .expect("stable continuation identity"),
            continuation.identity
        );
        let mut changed_posture = continuation.clone();
        changed_posture.process_posture_identity = identity('f');
        assert_ne!(
            launcher_startup_continuation_identity(&changed_posture)
                .expect("changed continuation identity"),
            continuation.identity
        );
        let mut unknown_kind = continuation;
        unknown_kind.message_kind = String::from("continue");
        assert_eq!(
            launcher_startup_continuation_identity(&unknown_kind),
            Err(ProtocolError::InvalidRecord)
        );
        let unit_name = format!(
            "ota-authority-invocation-{}.scope",
            child.request_identity.trim_start_matches("sha256:")
        );
        let mut scope = LauncherSystemdScopeV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: child.invocation_id.clone(),
            request_identity: child.request_identity.clone(),
            child_identity: child.identity.clone(),
            child_pid: child.pid,
            unit_name: unit_name.clone(),
            unit_object_path: format!("/org/freedesktop/systemd1/unit/{unit_name}"),
            slice: String::from("ota-authority-invocations.slice"),
            control_group: format!("/ota-authority-invocations.slice/{unit_name}"),
            delegate: false,
            kill_mode: String::from("control-group"),
            collect_mode: String::from("inactive-or-failed"),
        };
        scope.identity = launcher_systemd_scope_identity(&scope).expect("scope identity");
        assert_eq!(
            scope.identity,
            "sha256:7463099e41634f2d64d2ae741172cf8d0e8c3cd6dae757f9d7f9f683529047d0"
        );
        assert_eq!(
            launcher_systemd_scope_identity(&scope).expect("stable scope identity"),
            scope.identity
        );
        let mut changed_scope = scope.clone();
        changed_scope.child_pid += 1;
        assert_ne!(
            launcher_systemd_scope_identity(&changed_scope).expect("changed scope identity"),
            scope.identity
        );
        for alias in [
            format!("//{}/{}", scope.slice, scope.unit_name),
            format!("/{}/./{}", scope.slice, scope.unit_name),
            format!("/{}/{}/", scope.slice, scope.unit_name),
        ] {
            let mut aliased_scope = scope.clone();
            aliased_scope.control_group = alias;
            assert_eq!(
                launcher_systemd_scope_identity(&aliased_scope),
                Err(ProtocolError::InvalidRecord)
            );
        }
        let mut invalid_scope = scope;
        invalid_scope.delegate = true;
        assert_eq!(
            launcher_systemd_scope_identity(&invalid_scope),
            Err(ProtocolError::InvalidRecord)
        );

        let mut invalid_child = child;
        invalid_child.process_start_time_identity = String::from("pid-start");
        assert_eq!(
            launcher_child_process_identity(&invalid_child),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn protected_history_records_are_phase_bound_and_content_addressed() {
        let sha = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let archive_sha = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let snapshot_sha =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let sidecar_sha = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let mut query = LauncherHistoryQueryV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_QUERY.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            query_nonce: "query-nonce-1".into(),
            archive_identity: Some(sha.into()),
            query_identity: String::new(),
        };
        query.query_identity = launcher_history_query_v1_identity(&query).expect("query identity");

        let mut manifest = LauncherHistoryManifestV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_MANIFEST.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            query_identity: query.query_identity.clone(),
            repository_binding_identity: sha.into(),
            catalog_namespace_identity: sha.into(),
            operator_profile_identity: archive_sha.into(),
            operator_peer_identity: snapshot_sha.into(),
            operator_attribution: LauncherHistoryOperatorAttributionV1::NonAgent,
            operator_posture: LauncherHistoryOperatorPostureV1::LeastPrivilegeOperatorPeerVerified,
            catalog_entry_identities: vec![sha.into()],
            total_selected_count: 1,
            bounded_response_bytes: 1024,
            catalog_snapshot_identity: sha.into(),
            manifest_identity: String::new(),
        };
        manifest.manifest_identity =
            launcher_history_manifest_v1_identity(&manifest).expect("manifest identity");

        let mut archive_object = LauncherHistoryObjectV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_OBJECT.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            manifest_identity: manifest.manifest_identity.clone(),
            entry_ordinal: 0,
            catalog_identity: sha.into(),
            object_kind: LauncherHistoryObjectKindV1::Archive,
            content_identity: archive_sha.into(),
            byte_length: 4,
            chunk_count: 1,
            object_identity: String::new(),
        };
        archive_object.object_identity =
            launcher_history_object_v1_identity(&archive_object).expect("archive object identity");
        let mut snapshot_object = archive_object.clone();
        snapshot_object.object_kind = LauncherHistoryObjectKindV1::ContractSnapshot;
        snapshot_object.content_identity = snapshot_sha.into();
        snapshot_object.object_identity.clear();
        snapshot_object.object_identity = launcher_history_object_v1_identity(&snapshot_object)
            .expect("snapshot object identity");
        let mut sidecar_object = archive_object.clone();
        sidecar_object.object_kind = LauncherHistoryObjectKindV1::Sidecar;
        sidecar_object.content_identity = sidecar_sha.into();
        sidecar_object.object_identity.clear();
        sidecar_object.object_identity =
            launcher_history_object_v1_identity(&sidecar_object).expect("sidecar object identity");
        let mut archive_chunk = LauncherHistoryChunkV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_CHUNK.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            object_identity: archive_object.object_identity.clone(),
            chunk_ordinal: 0,
            bytes: b"test".to_vec(),
            chunk_identity: String::new(),
        };
        archive_chunk.chunk_identity =
            launcher_history_chunk_v1_identity(&archive_chunk).expect("chunk identity");
        let mut changed_chunk = archive_chunk.clone();
        changed_chunk.bytes[0] ^= 1;
        assert_ne!(
            launcher_history_chunk_v1_identity(&changed_chunk).expect("changed chunk identity"),
            archive_chunk.chunk_identity
        );

        let mut entry = LauncherHistoryEntryV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_ENTRY.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            manifest_identity: manifest.manifest_identity.clone(),
            entry_ordinal: 0,
            catalog_identity: sha.into(),
            archive_object_identity: archive_object.object_identity.clone(),
            contract_snapshot_object_identity: snapshot_object.object_identity.clone(),
            sidecar_object_identity: sidecar_object.object_identity.clone(),
            entry_identity: String::new(),
        };
        entry.entry_identity = launcher_history_entry_v1_identity(&entry).expect("entry identity");
        let mut aliased_entry = entry.clone();
        aliased_entry.contract_snapshot_object_identity =
            aliased_entry.archive_object_identity.clone();
        assert_eq!(
            launcher_history_entry_v1_identity(&aliased_entry),
            Err(ProtocolError::InvalidRecord)
        );

        let mut pre_query = LauncherHistoryPreQueryRefusalV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_PRE_QUERY_REFUSAL.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            refusal_nonce: "refusal-nonce-1".into(),
            reason: LauncherHistoryRefusalReasonV1::MalformedQuery,
            terminal_identity: String::new(),
        };
        pre_query.terminal_identity = launcher_history_pre_query_refusal_v1_identity(&pre_query)
            .expect("pre-query terminal identity");

        let mut query_refusal = LauncherHistoryQueryRefusalV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_QUERY_REFUSAL.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            query_identity: query.query_identity.clone(),
            reason: LauncherHistoryRefusalReasonV1::ResultTooLarge,
            terminal_identity: String::new(),
        };
        query_refusal.terminal_identity =
            launcher_history_query_refusal_v1_identity(&query_refusal)
                .expect("query terminal identity");

        let mut complete = LauncherHistoryManifestTerminalV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_MANIFEST_TERMINAL.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            query_identity: query.query_identity.clone(),
            manifest_identity: manifest.manifest_identity.clone(),
            returned_count: 1,
            posture: LauncherHistoryManifestPostureV1::Complete,
            terminal_identity: String::new(),
        };
        complete.terminal_identity = launcher_history_manifest_terminal_v1_identity(&complete)
            .expect("manifest terminal identity");

        assert!(is_sha256_identity(&pre_query.terminal_identity));
        assert!(is_sha256_identity(&query_refusal.terminal_identity));
        assert!(is_sha256_identity(&complete.terminal_identity));

        query_refusal.reason = LauncherHistoryRefusalReasonV1::MalformedQuery;
        assert_eq!(
            launcher_history_query_refusal_v1_identity(&query_refusal),
            Err(ProtocolError::InvalidRecord)
        );
        pre_query.reason = LauncherHistoryRefusalReasonV1::ResultTooLarge;
        assert_eq!(
            launcher_history_pre_query_refusal_v1_identity(&pre_query),
            Err(ProtocolError::InvalidRecord)
        );

        manifest.catalog_entry_identities.push(sha.into());
        manifest.total_selected_count = 2;
        assert_eq!(
            launcher_history_manifest_v1_identity(&manifest),
            Err(ProtocolError::InvalidRecord)
        );
        manifest.catalog_entry_identities.pop();
        manifest.total_selected_count = 1;
        let original_manifest_identity = manifest.manifest_identity.clone();
        manifest.operator_peer_identity = sidecar_sha.into();
        manifest.manifest_identity.clear();
        assert_ne!(
            launcher_history_manifest_v1_identity(&manifest)
                .expect("changed operator peer identity"),
            original_manifest_identity
        );
    }

    #[test]
    fn systemd_launcher_output_and_terminal_frames_are_strict() {
        let output = LauncherOutputFrameV1 {
            message_kind: LAUNCHER_OUTPUT.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: "request-123".into(),
            sequence: 1,
            stream: LauncherOutputStreamV1::Stdout,
            payload: vec![0, 159, 255],
        };
        assert_eq!(validate_launcher_output_frame_v1(&output), Ok(()));

        let largest_output = LauncherOutputFrameV1 {
            payload: vec![255; MAX_LAUNCHER_OUTPUT_PAYLOAD_BYTES_V1],
            ..output.clone()
        };
        assert_eq!(validate_launcher_output_frame_v1(&largest_output), Ok(()));
        let encoded = serde_json::to_vec(&largest_output).expect("output JSON");
        assert!(encoded.len() <= MAX_FRAME_BYTES);
        let too_large = LauncherOutputFrameV1 {
            payload: vec![255; MAX_LAUNCHER_OUTPUT_PAYLOAD_BYTES_V1 + 1],
            ..output
        };
        assert_eq!(
            validate_launcher_output_frame_v1(&too_large),
            Err(ProtocolError::InvalidRecord)
        );

        let complete = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: "request-123".into(),
            outcome: LauncherTerminalOutcomeV1::Completed,
            exit_code: Some(0),
            stage: None,
            finalization: None,
        };
        assert_eq!(validate_launcher_terminal_frame_v1(&complete), Ok(()));
        let terminal_identity =
            launcher_terminal_frame_v1_identity(&complete).expect("terminal identity");
        let mut terminal_persistence = LauncherTerminalPersistenceV1 {
            schema_version: 1,
            message_kind: LAUNCHER_TERMINAL_PERSISTENCE.into(),
            identity: String::new(),
            invocation_id: complete.invocation_id.clone(),
            terminal_identity: terminal_identity.clone(),
        };
        terminal_persistence.identity =
            launcher_terminal_persistence_v1_identity(&terminal_persistence)
                .expect("terminal persistence identity");
        assert_eq!(
            launcher_terminal_persistence_v1_identity(&terminal_persistence)
                .expect("stable terminal persistence identity"),
            terminal_persistence.identity
        );
        let mut substituted_persistence = terminal_persistence;
        substituted_persistence.terminal_identity = format!("sha256:{}", "f".repeat(64));
        assert_ne!(
            launcher_terminal_persistence_v1_identity(&substituted_persistence)
                .expect("substituted terminal persistence identity"),
            substituted_persistence.identity
        );

        let mut contradictory = complete;
        contradictory.exit_code = Some(1);
        assert_eq!(
            validate_launcher_terminal_frame_v1(&contradictory),
            Err(ProtocolError::InvalidRecord)
        );

        let posture_terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: "request-123".into(),
            outcome: LauncherTerminalOutcomeV1::Refused,
            exit_code: Some(2),
            stage: Some(LauncherTerminalStageV1::PostureAdmittedBoundaryRemoved),
            finalization: None,
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&posture_terminal),
            Ok(())
        );
        let attestation_terminal = LauncherTerminalFrameV1 {
            stage: Some(
                LauncherTerminalStageV1::AttestationAdmittedBeforeAuthorizationBoundaryRemoved,
            ),
            ..posture_terminal.clone()
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&attestation_terminal),
            Ok(())
        );
        let decision_terminal = LauncherTerminalFrameV1 {
            stage: Some(
                LauncherTerminalStageV1::AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved,
            ),
            ..posture_terminal.clone()
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&decision_terminal),
            Ok(())
        );
        let consumption_terminal = LauncherTerminalFrameV1 {
            stage: Some(
                LauncherTerminalStageV1::LeaseConsumedBeforeExecutionDisabledBoundaryRemoved,
            ),
            ..posture_terminal.clone()
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&consumption_terminal),
            Ok(())
        );
        let authority_refusal_terminal = LauncherTerminalFrameV1 {
            stage: Some(LauncherTerminalStageV1::AuthorityRefusedBoundaryRemoved),
            ..posture_terminal.clone()
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&authority_refusal_terminal),
            Ok(())
        );
        let protocol_refusal_terminal = LauncherTerminalFrameV1 {
            stage: Some(LauncherTerminalStageV1::PreAuthorizationProtocolRefusedBoundaryRemoved),
            ..posture_terminal.clone()
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&protocol_refusal_terminal),
            Ok(())
        );
        let contradictory_stage = LauncherTerminalFrameV1 {
            outcome: LauncherTerminalOutcomeV1::Failed,
            exit_code: Some(1),
            ..posture_terminal
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&contradictory_stage),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn selected_execution_terminal_binds_completion_persistence_and_cleanup() {
        let identity = |value: char| format!("sha256:{}", value.to_string().repeat(64));
        let mut completion = LauncherExecutionCompletionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_EXECUTION_COMPLETION.into(),
            invocation_id: "request-123".into(),
            lease_consumption_admission_identity: identity('1'),
            work_unit_identity: identity('2'),
            crossing_transaction_id: "crossing-123".into(),
            pending_crossing_transaction_identity: identity('8'),
            crossing_transaction_identity: identity('3'),
            receipt_archive_identity: Some(identity('9')),
            outcome: LauncherExecutionOutcomeV1::Completed,
            exit_code: Some(0),
            receipt_status: "recorded".into(),
        };
        completion.identity =
            launcher_execution_completion_v1_identity(&completion).expect("completion identity");

        let mut persistence = LauncherExecutionCompletionPersistenceV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE.into(),
            completion_identity: completion.identity.clone(),
        };
        persistence.identity = launcher_execution_completion_persistence_v1_identity(&persistence)
            .expect("persistence identity");
        assert_eq!(
            launcher_execution_completion_persistence_v1_identity(&persistence)
                .expect("stable persistence identity"),
            persistence.identity
        );

        let mut finalization = LauncherExecutionFinalizationV1 {
            schema_version: 1,
            identity: String::new(),
            completion,
            child_identity: identity('4'),
            scope_identity: identity('5'),
            child_exit_posture: None,
            observed_exit_code: Some(0),
            child_reaped: true,
            child_absent: None,
            scope_removed: true,
            cgroup_empty_or_absent: true,
            active_slot_removed: true,
        };
        finalization.identity = launcher_execution_finalization_v1_identity(&finalization)
            .expect("finalization identity");
        let terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: "request-123".into(),
            outcome: LauncherTerminalOutcomeV1::Completed,
            exit_code: Some(0),
            stage: Some(LauncherTerminalStageV1::SelectedExecutionCompletedBoundaryRemoved),
            finalization: Some(finalization.clone()),
        };
        assert_eq!(validate_launcher_terminal_frame_v1(&terminal), Ok(()));

        let mut recovered = finalization.clone();
        recovered.schema_version = 2;
        recovered.child_exit_posture =
            Some(LauncherChildExitPostureV1::RecoveredAbsentCompletionBound);
        recovered.observed_exit_code = None;
        recovered.child_reaped = false;
        recovered.child_absent = Some(true);
        recovered.identity = launcher_execution_finalization_v1_identity(&recovered)
            .expect("recovered finalization identity");
        let recovered_terminal = LauncherTerminalFrameV1 {
            exit_code: Some(0),
            finalization: Some(recovered.clone()),
            ..terminal.clone()
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&recovered_terminal),
            Ok(())
        );
        let mut recovered_without_completion_exit = recovered_terminal.clone();
        recovered_without_completion_exit.exit_code = None;
        assert_eq!(
            validate_launcher_terminal_frame_v1(&recovered_without_completion_exit),
            Err(ProtocolError::InvalidRecord)
        );

        let mut dishonest_recovery = recovered;
        dishonest_recovery.child_reaped = true;
        assert_eq!(
            launcher_execution_finalization_v1_identity(&dishonest_recovery),
            Err(ProtocolError::InvalidRecord)
        );

        let mut interrupted = finalization.clone();
        interrupted.completion.outcome = LauncherExecutionOutcomeV1::Interrupted;
        interrupted.completion.exit_code = Some(130);
        interrupted.completion.identity =
            launcher_execution_completion_v1_identity(&interrupted.completion)
                .expect("interrupted completion identity");
        interrupted.observed_exit_code = Some(130);
        interrupted.identity = launcher_execution_finalization_v1_identity(&interrupted)
            .expect("interrupted finalization identity");
        let interrupted_terminal = LauncherTerminalFrameV1 {
            outcome: LauncherTerminalOutcomeV1::Cancelled,
            exit_code: Some(130),
            stage: Some(LauncherTerminalStageV1::SelectedExecutionInterruptedBoundaryRemoved),
            finalization: Some(interrupted),
            ..terminal.clone()
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&interrupted_terminal),
            Ok(())
        );

        let mut missing_cleanup = finalization.clone();
        missing_cleanup.scope_removed = false;
        assert_eq!(
            launcher_execution_finalization_v1_identity(&missing_cleanup),
            Err(ProtocolError::InvalidRecord)
        );
        let mut substituted_child = finalization.clone();
        substituted_child.child_identity = identity('6');
        assert_ne!(
            launcher_execution_finalization_v1_identity(&substituted_child)
                .expect("substituted identity"),
            finalization.identity
        );

        let mut signed = SignedLauncherExecutionFinalizationV1 {
            schema_version: 1,
            identity: String::new(),
            finalization: finalization.clone(),
            producer_binding_identity: identity('7'),
            issued_at: String::from("2026-08-13T12:00:00Z"),
            key_id: String::from("launcher-attestor-2026"),
            algorithm: String::from("ed25519"),
            signature: String::from("signed-finalization"),
        };
        signed.identity = signed_launcher_execution_finalization_v1_identity(&signed)
            .expect("signed finalization identity");
        let frame = LauncherSignedExecutionFinalizationFrameV1 {
            message_kind: LAUNCHER_SIGNED_EXECUTION_FINALIZATION.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: finalization.completion.invocation_id.clone(),
            signed_finalization: signed.clone(),
        };
        assert_eq!(
            validate_launcher_signed_execution_finalization_frame_v1(&frame),
            Ok(())
        );

        let mut signed_archive = SignedLauncherFinalizationArchiveV1 {
            schema_version: 1,
            identity: String::new(),
            signed_finalization_identity: signed.identity.clone(),
            receipt_archive_identity: identity('9'),
            crossing_transaction_identity: finalization
                .completion
                .crossing_transaction_identity
                .clone(),
            producer_binding_identity: signed.producer_binding_identity.clone(),
            issued_at: String::from("2026-08-13T12:00:01Z"),
            key_id: signed.key_id.clone(),
            algorithm: String::from("ed25519"),
            signature: String::from("signed-archive"),
        };
        signed_archive.identity = signed_launcher_finalization_archive_v1_identity(&signed_archive)
            .expect("signed archive identity");
        let mut sidecar = LauncherFinalizationArchiveSidecarV1 {
            schema_version: 1,
            identity: String::new(),
            signed_finalization: signed.clone(),
            signed_archive: signed_archive.clone(),
        };
        sidecar.identity =
            launcher_finalization_archive_sidecar_v1_identity(&sidecar).expect("sidecar identity");
        assert_eq!(
            launcher_finalization_archive_sidecar_v1_identity(&sidecar)
                .expect("stable sidecar identity"),
            sidecar.identity
        );
        let mut substituted_archive = sidecar.clone();
        substituted_archive.signed_archive.receipt_archive_identity = identity('a');
        substituted_archive.signed_archive.identity =
            signed_launcher_finalization_archive_v1_identity(&substituted_archive.signed_archive)
                .expect("substituted signed archive identity");
        launcher_finalization_archive_sidecar_v1_identity(&substituted_archive)
            .expect_err("archive identity substitution must contradict signed completion");

        let mut archive_request = LauncherFinalizationArchiveRequestV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_ARCHIVE_REQUEST.into(),
            request_identity: String::new(),
            authority_id: String::from("authority-1"),
            launcher_request_identity: identity('a'),
            receipt_archive_identity: signed_archive.receipt_archive_identity.clone(),
            crossing_transaction_identity: signed_archive.crossing_transaction_identity.clone(),
            signed_finalization_identity: Some(signed.identity.clone()),
        };
        archive_request.request_identity =
            launcher_finalization_archive_request_v1_identity(&archive_request)
                .expect("archive request identity");
        let mut recovery_request = LauncherFinalizationRecoveryRequestV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_RECOVERY_REQUEST.into(),
            request_identity: String::new(),
            authority_id: archive_request.authority_id.clone(),
            launcher_request_identity: archive_request.launcher_request_identity.clone(),
        };
        recovery_request.request_identity =
            launcher_finalization_recovery_request_v1_identity(&recovery_request)
                .expect("recovery request identity");
        assert_eq!(
            launcher_finalization_recovery_request_v1_identity(&recovery_request)
                .expect("stable recovery request identity"),
            recovery_request.request_identity
        );
        let mut substituted_recovery = recovery_request;
        substituted_recovery.launcher_request_identity = identity('b');
        assert_ne!(
            launcher_finalization_recovery_request_v1_identity(&substituted_recovery)
                .expect("substituted recovery request identity"),
            substituted_recovery.request_identity
        );

        let mut archive_response = LauncherFinalizationArchiveResponseV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_ARCHIVE_RESPONSE.into(),
            response_identity: String::new(),
            request_identity: archive_request.request_identity.clone(),
            invocation_id: finalization.completion.invocation_id.clone(),
            sidecar_file_name: Some(String::from("repo-receipt-20260813.launcher-finalization")),
            sidecar: sidecar.clone(),
        };
        archive_response.response_identity =
            launcher_finalization_archive_response_v1_identity(&archive_response)
                .expect("archive response identity");
        let mut persistence = LauncherFinalizationArchivePersistenceV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE.into(),
            identity: String::new(),
            request_identity: archive_request.request_identity,
            sidecar_identity: sidecar.identity,
        };
        persistence.identity = launcher_finalization_archive_persistence_v1_identity(&persistence)
            .expect("archive persistence identity");
        assert_eq!(
            launcher_finalization_archive_persistence_v1_identity(&persistence)
                .expect("stable archive persistence identity"),
            persistence.identity
        );

        let mut signing_request = LauncherFinalizationSigningRequestV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_SIGNING_REQUEST.into(),
            request_identity: String::new(),
            finalization: finalization.clone(),
            producer_binding_identity: signed.producer_binding_identity.clone(),
            launcher_service_binding_identity: identity('b'),
            launcher_configuration_identity: identity('c'),
            launcher_executable_identity: identity('d'),
            launcher_profile_identity: identity('e'),
        };
        signing_request.request_identity =
            launcher_finalization_signing_request_v1_identity(&signing_request)
                .expect("signing request identity");
        let mut signing_response = LauncherFinalizationSigningResponseV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_SIGNING_RESPONSE.into(),
            request_identity: signing_request.request_identity.clone(),
            signed_finalization: signed,
            response_identity: String::new(),
        };
        signing_response.response_identity =
            launcher_finalization_signing_response_v1_identity(&signing_response)
                .expect("signing response identity");
        assert_eq!(
            launcher_finalization_signing_response_v1_identity(&signing_response)
                .expect("stable signing response identity"),
            signing_response.response_identity
        );

        let mut wrong_stage = terminal;
        wrong_stage.stage = Some(LauncherTerminalStageV1::SelectedExecutionFailedBoundaryRemoved);
        wrong_stage.outcome = LauncherTerminalOutcomeV1::Failed;
        wrong_stage.exit_code = Some(1);
        assert_eq!(
            validate_launcher_terminal_frame_v1(&wrong_stage),
            Err(ProtocolError::InvalidRecord)
        );
        let mut wrong_invocation = wrong_stage;
        wrong_invocation.stage =
            Some(LauncherTerminalStageV1::SelectedExecutionCompletedBoundaryRemoved);
        wrong_invocation.outcome = LauncherTerminalOutcomeV1::Completed;
        wrong_invocation.exit_code = Some(0);
        wrong_invocation.invocation_id = String::from("request-substituted");
        assert_eq!(
            validate_launcher_terminal_frame_v1(&wrong_invocation),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn authorization_decision_relay_binds_core_verification() {
        let identity = |value: char| format!("sha256:{}", value.to_string().repeat(64));
        let request_identity = identity('1');
        let decision = SignedBrokerMessage {
            payload: AuthorizationDecisionPayload {
                message_kind: AUTHORIZATION_DECISION.into(),
                request_identity: request_identity.clone(),
                binding_identity: identity('2'),
                authority_id: String::from("release"),
                attestation_identity: identity('3'),
                challenge_nonce_commitment: identity('4'),
                work_unit_identity: identity('5'),
                contract_identity: identity('6'),
                semantic_scope_identity: identity('7'),
                decision: AuthorizationDecision::Allowed,
                approval_reference: Some(String::from("approval:1")),
                broker_revision: 1,
                issued_at: String::from("2026-08-11T00:00:00Z"),
                expires_at: String::from("2026-08-11T00:01:00Z"),
            },
            key_id: String::from("broker-key"),
            algorithm: String::from("ed25519"),
            signature: String::from("signature"),
        };
        let decision_identity =
            message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), &decision)
                .expect("decision identity");
        let mut admission = AuthorizationDecisionAdmissionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: AUTHORIZATION_DECISION_ADMISSION.into(),
            request_identity: request_identity.clone(),
            authorization_decision_identity: decision_identity.clone(),
            binding_identity: decision.payload.binding_identity.clone(),
            attestation_identity: decision.payload.attestation_identity.clone(),
            work_unit_identity: decision.payload.work_unit_identity.clone(),
            contract_identity: decision.payload.contract_identity.clone(),
            semantic_scope_identity: decision.payload.semantic_scope_identity.clone(),
            decision: AuthorizationDecision::Allowed,
        };
        admission.identity =
            authorization_decision_admission_v1_identity(&admission).expect("admission identity");
        let mut evidence = AuthorizationDecisionRelayEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            request_identity,
            authorization_decision: decision,
            authorization_decision_identity: decision_identity,
            admission,
        };
        evidence.identity = authorization_decision_relay_evidence_v1_identity(&evidence)
            .expect("relay evidence identity");
        assert_eq!(
            authorization_decision_relay_evidence_v1_identity(&evidence)
                .expect("stable relay identity"),
            evidence.identity
        );
        let mut substituted = evidence;
        substituted.admission.semantic_scope_identity = identity('8');
        substituted.admission.identity =
            authorization_decision_admission_v1_identity(&substituted.admission)
                .expect("substituted admission identity");
        assert_eq!(
            authorization_decision_relay_evidence_v1_identity(&substituted),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn lease_consumption_relay_binds_the_exact_consumed_exchange() {
        let identity = |value: char| format!("sha256:{}", value.to_string().repeat(64));
        let prepared_lease = SignedBrokerMessage {
            payload: PreparedLeasePayload {
                message_kind: LEASE_ISSUANCE.into(),
                authorization_decision_identity: identity('1'),
                binding_identity: identity('2'),
                authority_id: String::from("release"),
                attestation_identity: identity('3'),
                challenge_nonce_commitment: identity('4'),
                work_unit_identity: identity('5'),
                contract_identity: identity('6'),
                semantic_scope_identity: identity('7'),
                runner_principal: String::from("ota-runner"),
                broker_revision: 1,
                lease_sequence: 1,
                issued_at: String::from("2026-08-12T00:00:00Z"),
                expires_at: String::from("2026-08-12T00:01:00Z"),
            },
            key_id: String::from("broker-key"),
            algorithm: String::from("ed25519"),
            signature: String::from("signature"),
        };
        let prepared_lease_identity =
            message_identity(LEASE_ISSUANCE_DOMAIN_V1.as_bytes(), &prepared_lease)
                .expect("prepared lease identity");
        let consume_request = LeaseConsumeRequest {
            message_kind: LEASE_CONSUME.into(),
            binding_identity: prepared_lease.payload.binding_identity.clone(),
            lease_identity: prepared_lease_identity.clone(),
            challenge_nonce_commitment: prepared_lease.payload.challenge_nonce_commitment.clone(),
            work_unit_identity: prepared_lease.payload.work_unit_identity.clone(),
            crossing_transaction_id: String::from("crossing-1"),
            crossing_transaction_identity: identity('8'),
        };
        let consume_request_identity =
            message_identity(LEASE_CONSUME_DOMAIN_V1.as_bytes(), &consume_request)
                .expect("consume request identity");
        let mut intent = LeaseConsumptionIntentRelayEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            authorization_decision_relay_identity: identity('9'),
            prepared_lease: prepared_lease.clone(),
            prepared_lease_identity: prepared_lease_identity.clone(),
            consume_request: consume_request.clone(),
            consume_request_identity: consume_request_identity.clone(),
        };
        intent.identity = lease_consumption_intent_relay_evidence_v1_identity(&intent)
            .expect("consumption intent identity");
        assert_eq!(
            lease_consumption_intent_relay_evidence_v1_identity(&intent)
                .expect("stable consumption intent identity"),
            intent.identity
        );
        let mut substituted_intent = intent.clone();
        substituted_intent.consume_request.work_unit_identity = identity('a');
        assert_eq!(
            lease_consumption_intent_relay_evidence_v1_identity(&substituted_intent),
            Err(ProtocolError::InvalidRecord)
        );
        let consume_response = SignedBrokerMessage {
            payload: LeaseConsumeResponsePayload {
                message_kind: LEASE_CONSUME_RESPONSE.into(),
                consume_request_identity: consume_request_identity.clone(),
                binding_identity: consume_request.binding_identity.clone(),
                lease_identity: prepared_lease_identity.clone(),
                challenge_nonce_commitment: consume_request.challenge_nonce_commitment.clone(),
                work_unit_identity: consume_request.work_unit_identity.clone(),
                crossing_transaction_id: consume_request.crossing_transaction_id.clone(),
                crossing_transaction_identity: consume_request
                    .crossing_transaction_identity
                    .clone(),
                state: LeaseConsumeState::Consumed,
                broker_revision: 2,
                consumed_at: String::from("2026-08-12T00:00:01Z"),
            },
            key_id: String::from("broker-key"),
            algorithm: String::from("ed25519"),
            signature: String::from("signature"),
        };
        let consume_response_identity = message_identity(
            LEASE_CONSUME_RESPONSE_DOMAIN_V1.as_bytes(),
            &consume_response,
        )
        .expect("consume response identity");
        let mut admission = LeaseConsumptionAdmissionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LEASE_CONSUMPTION_ADMISSION.into(),
            binding_identity: consume_request.binding_identity.clone(),
            prepared_lease_identity: prepared_lease_identity.clone(),
            consume_request_identity: consume_request_identity.clone(),
            consume_response_identity: consume_response_identity.clone(),
            work_unit_identity: consume_request.work_unit_identity.clone(),
            crossing_transaction_id: consume_request.crossing_transaction_id.clone(),
            crossing_transaction_identity: consume_request.crossing_transaction_identity.clone(),
        };
        admission.identity = lease_consumption_admission_v1_identity(&admission)
            .expect("consumption admission identity");
        let mut evidence = LeaseConsumptionRelayEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            authorization_decision_relay_identity: identity('9'),
            prepared_lease,
            prepared_lease_identity,
            consume_request,
            consume_request_identity,
            consume_response,
            consume_response_identity,
            admission,
        };
        evidence.identity = lease_consumption_relay_evidence_v1_identity(&evidence)
            .expect("consumption relay identity");
        assert_eq!(
            lease_consumption_relay_evidence_v1_identity(&evidence)
                .expect("stable consumption relay identity"),
            evidence.identity
        );

        evidence.consume_response.payload.state = LeaseConsumeState::Revoked;
        evidence.consume_response_identity = message_identity(
            LEASE_CONSUME_RESPONSE_DOMAIN_V1.as_bytes(),
            &evidence.consume_response,
        )
        .expect("substituted response identity");
        evidence.admission.consume_response_identity = evidence.consume_response_identity.clone();
        evidence.admission.identity = lease_consumption_admission_v1_identity(&evidence.admission)
            .expect("substituted admission identity");
        assert_eq!(
            lease_consumption_relay_evidence_v1_identity(&evidence),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn lease_consumption_persistence_binds_the_exact_core_admission() {
        let identity = |value: char| format!("sha256:{}", value.to_string().repeat(64));
        let mut persistence = LeaseConsumptionPersistenceV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LEASE_CONSUMPTION_PERSISTENCE.into(),
            consumption_admission_identity: identity('a'),
        };
        persistence.identity =
            lease_consumption_persistence_v1_identity(&persistence).expect("persistence identity");
        assert_eq!(
            lease_consumption_persistence_v1_identity(&persistence)
                .expect("stable persistence identity"),
            persistence.identity
        );
        persistence.consumption_admission_identity = identity('b');
        assert_ne!(
            lease_consumption_persistence_v1_identity(&persistence)
                .expect("substituted persistence identity"),
            persistence.identity
        );
    }

    #[test]
    fn message_identity_is_canonical() {
        let first = serde_json::json!({"b": 2, "a": 1});
        let second = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(
            message_identity(b"test-domain\0", &first).expect("first"),
            message_identity(b"test-domain\0", &second).expect("second")
        );
    }

    #[test]
    fn protocol_message_sequence_is_stable() {
        assert_eq!(
            [
                CHALLENGE_REQUEST,
                ATTESTATION_RESPONSE,
                AUTHORIZATION_REQUEST,
                AUTHORIZATION_DECISION,
                LEASE_ISSUANCE,
                LEASE_CONSUME,
                LEASE_CONSUME_RESPONSE,
                LEASE_CONSUMPTION_QUERY,
                LEASE_CONSUMPTION_STATUS,
            ],
            [
                "challenge_request",
                "attestation_response",
                "authorization_request",
                "authorization_decision",
                "lease_issuance",
                "lease_consume",
                "lease_consume_response",
                "lease_consumption_query",
                "lease_consumption_status",
            ]
        );
    }

    #[test]
    fn canonical_domain_and_identity_vectors_are_stable() {
        assert_eq!(
            BROKER_BINDING_IDENTITY_DOMAIN_V1,
            b"ota.crossing-broker.binding.v1\0"
        );
        assert_eq!(
            BROKER_BINDING_IDENTITY_DOMAIN_V2,
            b"ota.crossing-broker.binding.v2\0"
        );
        assert_eq!(
            ATTESTATION_RESPONSE_DOMAIN_V2,
            "ota-crossing-broker/attestation-response/v2"
        );
        assert_eq!(
            ATTESTATION_IDENTITY_DOMAIN_V2,
            b"ota.crossing-broker.attestation.v2\0"
        );
        assert_eq!(
            SYSTEMD_LAUNCHER_SERVICE_CONFIGURATION_IDENTITY_DOMAIN_V1,
            b"ota.authority-launcher.systemd-service-configuration.v1\0"
        );
        assert_eq!(
            LAUNCHER_INVOCATION_REQUEST_IDENTITY_DOMAIN_V1,
            b"ota.authority-launcher.invocation-request.v1\0"
        );
        assert_eq!(
            LAUNCHER_WORKING_DIRECTORY_IDENTITY_DOMAIN_V1,
            b"ota.authority-launcher.working-directory.v1\0"
        );
        assert_eq!(
            LAUNCHER_CHILD_PROCESS_IDENTITY_DOMAIN_V1,
            b"ota.authority-launcher.child-process.v1\0"
        );
        assert_eq!(
            LAUNCHER_ATTESTATION_CLAIMS_IDENTITY_DOMAIN_V3,
            b"ota.authority-launcher.attestation-claims.v3\0"
        );
        assert_eq!(
            LAUNCHER_ATTESTATION_SIGNING_REQUEST_IDENTITY_DOMAIN_V1,
            b"ota.authority-launcher.attestation-signing-request.v1\0"
        );
        assert_eq!(
            LAUNCHER_ATTESTATION_SIGNING_RESPONSE_IDENTITY_DOMAIN_V1,
            b"ota.authority-launcher.attestation-signing-response.v1\0"
        );
        assert_eq!(
            LAUNCHER_FINALIZATION_RECOVERY_REQUEST_IDENTITY_DOMAIN_V1,
            b"ota.authority-launcher.finalization-recovery-request.v1\0"
        );
        assert_eq!(
            [
                CHALLENGE_REQUEST_DOMAIN_V1,
                ATTESTATION_RESPONSE_DOMAIN_V1,
                AUTHORIZATION_REQUEST_DOMAIN_V1,
                AUTHORIZATION_DECISION_DOMAIN_V1,
                LEASE_ISSUANCE_DOMAIN_V1,
                LEASE_CONSUME_DOMAIN_V1,
                LEASE_CONSUME_RESPONSE_DOMAIN_V1,
                LEASE_CONSUMPTION_QUERY_DOMAIN_V1,
                LEASE_CONSUMPTION_STATUS_DOMAIN_V1,
            ],
            [
                "ota-crossing-broker/challenge-request/v1",
                "ota-crossing-broker/attestation-response/v1",
                "ota-crossing-broker/authorization-request/v1",
                "ota-crossing-broker/authorization-decision/v1",
                "ota-crossing-broker/lease-issuance/v1",
                "ota-crossing-broker/lease-consume/v1",
                "ota-crossing-broker/lease-consume-response/v1",
                "ota-crossing-broker/lease-consumption-query/v1",
                "ota-crossing-broker/lease-consumption-status/v1",
            ]
        );
        let commitment = nonce_commitment(b"ota-protocol-vector-v1");
        assert_eq!(
            commitment,
            "sha256:f82a6e1b6f0a0dba3073a35ee457e753b35ed3716455e7a4a1f4e59579338038"
        );
        assert_eq!(
            derive_work_unit_identity(
                "sha256:binding",
                "sha256:contract",
                "sha256:scope",
                commitment.as_str(),
            )
            .expect("work unit"),
            "sha256:7a56b64f47af50db7d230e88681a8b86efa38ba1cc5bd6d9d905d3ce2d1fd009"
        );
    }

    #[test]
    fn runtime_boundary_profiles_are_closed_ordered_and_content_addressed() {
        let base = protected_launcher_profile_v1();
        let image = protected_launcher_image_profile_v1();

        assert_eq!(base.schema_version, 1);
        assert_eq!(base.profile_id, PROTECTED_LAUNCHER_PROFILE_ID_V1);
        assert_eq!(base.observations.len(), 11);
        assert_eq!(image.profile_id, PROTECTED_LAUNCHER_IMAGE_PROFILE_ID_V1);
        assert_eq!(image.observations.len(), 13);
        assert_eq!(
            base.observations[0].semantic_identity,
            RuntimeBoundarySemanticIdentityPosture::Forbidden
        );
        assert_eq!(
            base.observations[9].semantic_identity,
            RuntimeBoundarySemanticIdentityPosture::Required
        );
        assert_eq!(
            base.observations[10].semantic_identity,
            RuntimeBoundarySemanticIdentityPosture::Required
        );
        assert_eq!(
            &image.observations[..base.observations.len()],
            base.observations.as_slice()
        );
        assert_eq!(
            image.observations[11],
            RuntimeBoundaryObservationRequirement {
                name: RuntimeBoundaryObservationName::RunnerImageIdentityBound,
                evidence_method: RuntimeBoundaryEvidenceMethod::ProtectedImageMeasurement,
                semantic_identity: RuntimeBoundarySemanticIdentityPosture::Required,
            }
        );
        assert_eq!(
            image.observations[12],
            RuntimeBoundaryObservationRequirement {
                name: RuntimeBoundaryObservationName::HardeningProfileIdentityBound,
                evidence_method: RuntimeBoundaryEvidenceMethod::ProtectedProfileMeasurement,
                semantic_identity: RuntimeBoundarySemanticIdentityPosture::Required,
            }
        );
        assert_eq!(
            runtime_boundary_profile_identity(&base).expect("base profile identity"),
            "sha256:8a0c2b279b90840a038525f841f896016030a9f61a054fb759da4bb197faf4e8"
        );
        assert_eq!(
            runtime_boundary_profile_identity(&image).expect("image profile identity"),
            "sha256:8e59ecce1e92370ad682d9a73c4e710f86f302122f9bd1dc7c829f0b11aa5f7b"
        );
        assert_eq!(
            runtime_boundary_profile_by_id(PROTECTED_LAUNCHER_PROFILE_ID_V1),
            Some(base)
        );
        assert!(runtime_boundary_profile_by_id("unknown-profile").is_none());
    }

    #[test]
    fn systemd_launcher_profiles_are_closed_ordered_and_content_addressed() {
        let launcher = systemd_launcher_profile_v1();
        let separated_producer = systemd_launcher_profile_v2();
        let process_inspection = systemd_launcher_profile_v3();
        let principal = systemd_job_principal_profile_v1();
        let systemd_principal = systemd_job_principal_profile_v2();

        assert_eq!(launcher.schema_version, 1);
        assert_eq!(launcher.profile_id, SYSTEMD_LAUNCHER_PROFILE_ID_V1);
        assert_eq!(launcher.service_settings.len(), 29);
        assert_eq!(launcher.socket_settings.len(), 7);
        assert_eq!(launcher.invocation_scope_settings.len(), 5);
        assert_eq!(launcher.evidence_sources.len(), 8);
        assert_eq!(separated_producer.schema_version, 1);
        assert_eq!(
            separated_producer.profile_id,
            SYSTEMD_LAUNCHER_PROFILE_ID_V2
        );
        assert_eq!(separated_producer.service_settings.len(), 28);
        assert!(separated_producer.service_settings.iter().all(|setting| {
            setting.name != "LoadCredentialEncrypted"
                && !setting.value.contains("encrypted_attestor_credential")
        }));
        assert!(separated_producer.service_settings.iter().any(|setting| {
            setting.name == "ReadOnlyPaths"
                && setting.value.contains("<producer_public_verifier_set>")
                && setting.value.contains("<producer_socket_metadata>")
        }));
        assert_eq!(
            systemd_launcher_profile_by_id(SYSTEMD_LAUNCHER_PROFILE_ID_V2),
            Some(separated_producer.clone())
        );
        assert_eq!(
            process_inspection.profile_id,
            SYSTEMD_LAUNCHER_PROFILE_ID_V3
        );
        assert!(process_inspection.service_settings.iter().any(|setting| {
            setting.name == "CapabilityBoundingSet"
                && setting.value == "CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_PTRACE CAP_DAC_OVERRIDE"
        }));
        assert_eq!(
            systemd_launcher_profile_by_id(SYSTEMD_LAUNCHER_PROFILE_ID_V3),
            Some(process_inspection.clone())
        );
        assert_eq!(principal.schema_version, 1);
        assert_eq!(principal.profile_id, SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1);
        assert_eq!(principal.requirements.len(), 18);
        assert_eq!(
            systemd_principal.profile_id,
            SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2
        );
        assert_eq!(systemd_principal.requirements.len(), 18);
        assert!(systemd_principal.requirements.iter().any(|requirement| {
            requirement.requirement
                == SystemdJobPrincipalRequirement::PeerSupplementaryGroupsLimitedToPrimary
        }));
        assert!(systemd_principal.requirements.iter().all(|requirement| {
            requirement.requirement != SystemdJobPrincipalRequirement::PeerSupplementaryGroupsEmpty
        }));
        assert_eq!(
            systemd_job_principal_profile_by_id(SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2),
            Some(systemd_principal.clone())
        );

        let launcher_identity =
            systemd_launcher_profile_identity(&launcher).expect("launcher profile identity");
        let principal_identity = systemd_job_principal_profile_identity(&principal)
            .expect("job principal profile identity");
        assert_eq!(
            launcher_identity,
            "sha256:32c49f19799e065d341c900a4ce0d7756669c0c0d4e990ffe81bbcda06291930"
        );
        assert_eq!(
            systemd_launcher_profile_identity(&separated_producer)
                .expect("separated producer profile identity"),
            "sha256:c816a49e01120bf1f793aedcfec094ca0f23a8ee80f1c7e5bed4c2d9c797cb42"
        );
        assert_eq!(
            systemd_launcher_profile_identity(&process_inspection)
                .expect("process-inspection profile identity"),
            "sha256:1d0ef44c24b6ec21dc0c462edd52c5197ae35a4a1728a98cd93b92d6f106dfaf"
        );
        assert_eq!(
            principal_identity,
            "sha256:e69ef375070bbb4f5616ba46b6f29b9a987372909016d1a1dfa40a5d4daae93d"
        );

        let mut producer = LauncherAttestationProducerBindingV1 {
            schema_version: 1,
            identity: String::new(),
            producer_id: String::from("systemd-attestor-v1"),
            socket_path: String::from(SYSTEMD_ATTESTOR_SOCKET_PATH_V1),
            service_unit: String::from(SYSTEMD_ATTESTOR_SERVICE_UNIT_V1),
            launcher_service_unit: String::from(SYSTEMD_LAUNCHER_SERVICE_UNIT_V1),
            launcher_service_binding_identity: format!("sha256:{}", "5".repeat(64)),
            launcher_configuration_identity: format!("sha256:{}", "6".repeat(64)),
            launcher_profile_identity: format!("sha256:{}", "7".repeat(64)),
            launcher_executable_identity: format!("sha256:{}", "1".repeat(64)),
            producer_executable_identity: format!("sha256:{}", "2".repeat(64)),
            verifier_key_set_identity: format!("sha256:{}", "3".repeat(64)),
            signing_key_id: String::from("systemd-attestor-2026-01"),
            signing_public_key: String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            signing_public_key_identity: format!("sha256:{}", "4".repeat(64)),
            signing_key_not_before: String::from("2026-08-01T00:00:00Z"),
            signing_key_not_after: String::from("2026-09-01T00:00:00Z"),
            issuer: String::from("systemd-attestor"),
            audience: String::from("ota-crossing-broker"),
            maximum_attestation_age_seconds: 120,
            verifier_maximum_age_seconds: 180,
            maximum_request_bytes: MAX_FRAME_BYTES,
            read_write_timeout_seconds: 5,
            issuance_state_directory: String::from("/var/lib/ota/authority-attestor/issuance"),
            signing_credential_name: String::from("ota-attestor-ed25519"),
        };
        producer.identity = launcher_attestation_producer_binding_v1_identity(&producer)
            .expect("producer binding identity");
        validate_launcher_attestation_producer_binding_v1(&producer)
            .expect("valid producer binding");
        let mut changed = producer.clone();
        changed.maximum_attestation_age_seconds = 121;
        assert_eq!(
            validate_launcher_attestation_producer_binding_v1(&changed),
            Err(ProtocolError::InvalidRecord)
        );
        let mut invalid_public_key = producer.clone();
        invalid_public_key.signing_public_key = String::from("not-a-public-key");
        assert_eq!(
            validate_launcher_attestation_producer_binding_v1(&invalid_public_key),
            Err(ProtocolError::InvalidRecord)
        );
        let mut invalid_verifier_window = producer.clone();
        invalid_verifier_window.verifier_maximum_age_seconds = 119;
        assert_eq!(
            validate_launcher_attestation_producer_binding_v1(&invalid_verifier_window),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn principal_mapping_and_process_posture_identities_are_self_excluding() {
        let job_peer = UnixPrincipalIdentity {
            real_uid: 1001,
            effective_uid: 1001,
            saved_uid: 1001,
            filesystem_uid: 1001,
            real_gid: 1001,
            effective_gid: 1001,
            saved_gid: 1001,
            filesystem_gid: 1001,
        };
        let execution = UnixPrincipalIdentity {
            real_uid: 1002,
            effective_uid: 1002,
            saved_uid: 1002,
            filesystem_uid: 1002,
            real_gid: 1002,
            effective_gid: 1002,
            saved_gid: 1002,
            filesystem_gid: 1002,
        };
        let mut mapping = LauncherPrincipalMappingV1 {
            schema_version: 1,
            identity: String::new(),
            job_peer,
            execution,
            job_principal_profile_identity: systemd_job_principal_profile_identity(
                &systemd_job_principal_profile_v1(),
            )
            .expect("job principal profile identity"),
            launcher_session_binding_identity:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        };
        mapping.identity =
            launcher_principal_mapping_identity(&mapping).expect("principal mapping identity");
        assert_eq!(
            launcher_principal_mapping_identity(&mapping).expect("stable mapping identity"),
            mapping.identity
        );

        let mut changed = mapping.clone();
        changed.execution.real_uid = 1003;
        changed.execution.effective_uid = 1003;
        changed.execution.saved_uid = 1003;
        changed.execution.filesystem_uid = 1003;
        assert_ne!(
            launcher_principal_mapping_identity(&changed).expect("changed mapping identity"),
            mapping.identity
        );

        let mut posture = OtaProcessPostureV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: OTA_PROCESS_POSTURE.into(),
            pid: 4242,
            process_start_time_identity:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ota_binary_identity:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            no_new_privs: true,
            dumpable: 0,
            ptracer_clear_applied: true,
            principal_mapping_identity: mapping.identity.clone(),
        };
        posture.identity =
            ota_process_posture_identity(&posture).expect("process posture identity");
        assert_eq!(
            ota_process_posture_identity(&posture).expect("stable posture identity"),
            posture.identity
        );

        let value = serde_json::to_value(&posture).expect("process posture JSON");
        assert!(serde_json::from_value::<OtaProcessPostureV1>(value).is_ok());
        let mut unknown = serde_json::to_value(&posture).expect("process posture JSON");
        unknown["caller_label"] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<OtaProcessPostureV1>(unknown).is_err());

        for invalid in [
            {
                let mut value = mapping.clone();
                value.schema_version = 2;
                value
            },
            {
                let mut value = mapping.clone();
                value.execution = value.job_peer.clone();
                value
            },
            {
                let mut value = mapping.clone();
                value.execution.effective_uid += 1;
                value
            },
            {
                let mut value = mapping.clone();
                value.job_principal_profile_identity =
                    "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        .into();
                value
            },
        ] {
            assert_eq!(
                launcher_principal_mapping_identity(&invalid),
                Err(ProtocolError::InvalidRecord)
            );
        }

        for invalid in [
            {
                let mut value = posture.clone();
                value.schema_version = 2;
                value
            },
            {
                let mut value = posture.clone();
                value.message_kind = "challenge_request".into();
                value
            },
            {
                let mut value = posture.clone();
                value.dumpable = 1;
                value
            },
            {
                let mut value = posture.clone();
                value.ptracer_clear_applied = false;
                value
            },
        ] {
            assert_eq!(
                ota_process_posture_identity(&invalid),
                Err(ProtocolError::InvalidRecord)
            );
        }

        let mut instance = SystemdProtectedLauncherInstanceEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            principal_mapping: mapping,
            process_posture: posture,
            systemd_launcher_profile_identity: systemd_launcher_profile_identity(
                &systemd_launcher_profile_v1(),
            )
            .expect("launcher profile identity"),
            systemd_job_principal_profile_identity: systemd_job_principal_profile_identity(
                &systemd_job_principal_profile_v1(),
            )
            .expect("job principal profile identity"),
            launcher_session_binding_identity:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            systemd_invocation_identity:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
            working_directory_identity:
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
            child_process_identity:
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
        };
        instance.identity = systemd_protected_launcher_instance_identity(&instance)
            .expect("launcher instance identity");
        assert_eq!(
            systemd_protected_launcher_instance_identity(&instance)
                .expect("stable launcher instance identity"),
            instance.identity
        );
        let mut complete = SystemdProtectedLauncherInstanceEvidenceV2 {
            schema_version: 2,
            identity: String::new(),
            instance_v1: instance.clone(),
            launcher_observations: systemd_launcher_profile_v1()
                .evidence_sources
                .into_iter()
                .map(|source| SystemdLauncherObservation {
                    source,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_systemd_protected_launcher"),
                    evidence_identity: None,
                })
                .collect(),
            job_principal_observations: systemd_job_principal_profile_v1()
                .requirements
                .into_iter()
                .map(|required| SystemdJobPrincipalObservation {
                    requirement: required.requirement,
                    evidence_methods: required.evidence_methods,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_systemd_protected_launcher"),
                    evidence_identity: None,
                })
                .collect(),
        };
        complete.identity = systemd_protected_launcher_instance_v2_identity(&complete)
            .expect("complete launcher instance identity");
        assert_eq!(
            systemd_protected_launcher_instance_v2_identity(&complete)
                .expect("stable complete launcher instance identity"),
            complete.identity
        );
        let legacy_complete = complete.clone();
        assert!(systemd_protected_launcher_instance_v2_identity(&legacy_complete).is_ok());
        let mut separated_producer_complete = complete.clone();
        separated_producer_complete
            .instance_v1
            .systemd_launcher_profile_identity =
            systemd_launcher_profile_identity(&systemd_launcher_profile_v2())
                .expect("separated producer profile identity");
        separated_producer_complete.instance_v1.identity =
            systemd_protected_launcher_instance_identity(&separated_producer_complete.instance_v1)
                .expect("separated producer instance identity");
        separated_producer_complete.identity =
            systemd_protected_launcher_instance_v2_identity(&separated_producer_complete)
                .expect("separated producer complete identity");
        assert_ne!(separated_producer_complete.identity, complete.identity);

        let launcher_profile_v3 = systemd_launcher_profile_v3();
        let job_profile_v2 = systemd_job_principal_profile_v2();
        let launcher_profile_v3_identity = systemd_launcher_profile_identity(&launcher_profile_v3)
            .expect("v3 launcher profile identity");
        let job_profile_v2_identity = systemd_job_principal_profile_identity(&job_profile_v2)
            .expect("v2 job-principal profile identity");
        let mut instance_v3 = instance.clone();
        instance_v3.principal_mapping.job_principal_profile_identity =
            job_profile_v2_identity.clone();
        instance_v3.principal_mapping.identity =
            launcher_principal_mapping_identity(&instance_v3.principal_mapping)
                .expect("v3 principal mapping identity");
        instance_v3.process_posture.principal_mapping_identity =
            instance_v3.principal_mapping.identity.clone();
        instance_v3.process_posture.identity =
            ota_process_posture_identity(&instance_v3.process_posture)
                .expect("v3 process posture identity");
        instance_v3.systemd_launcher_profile_identity = launcher_profile_v3_identity;
        instance_v3.systemd_job_principal_profile_identity = job_profile_v2_identity;
        assert_eq!(
            systemd_protected_launcher_instance_identity(&instance_v3),
            Err(ProtocolError::InvalidRecord)
        );
        instance_v3.identity =
            systemd_protected_launcher_instance_v3_foundation_identity(&instance_v3)
                .expect("v3 launcher foundation identity");
        let mut complete_v3 = SystemdProtectedLauncherInstanceEvidenceV2 {
            schema_version: 3,
            identity: String::new(),
            instance_v1: instance_v3,
            launcher_observations: launcher_profile_v3
                .evidence_sources
                .into_iter()
                .map(|source| SystemdLauncherObservation {
                    source,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_systemd_protected_launcher"),
                    evidence_identity: Some(format!("sha256:{}", "3".repeat(64))),
                })
                .collect(),
            job_principal_observations: job_profile_v2
                .requirements
                .into_iter()
                .map(|required| SystemdJobPrincipalObservation {
                    requirement: required.requirement,
                    evidence_methods: required.evidence_methods,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_systemd_protected_launcher"),
                    evidence_identity: Some(format!("sha256:{}", "4".repeat(64))),
                })
                .collect(),
        };
        complete_v3.identity = systemd_protected_launcher_instance_v2_identity(&complete_v3)
            .expect("complete v3 launcher instance identity");
        let mut stripped_current = complete_v3.clone();
        stripped_current.launcher_observations[0].evidence_identity = None;
        assert!(systemd_protected_launcher_instance_v2_identity(&stripped_current).is_err());
        let mut v3_profiles_in_legacy_schema = complete_v3.clone();
        v3_profiles_in_legacy_schema.schema_version = 2;
        v3_profiles_in_legacy_schema.identity.clear();
        for observation in &mut v3_profiles_in_legacy_schema.launcher_observations {
            observation.evidence_identity = None;
        }
        for observation in &mut v3_profiles_in_legacy_schema.job_principal_observations {
            observation.evidence_identity = None;
        }
        assert_eq!(
            systemd_protected_launcher_instance_v2_identity(&v3_profiles_in_legacy_schema),
            Err(ProtocolError::InvalidRecord)
        );
        let attestation = SignedLauncherAttestationV3 {
            payload: LauncherAttestationPayloadV3 {
                message_kind: ATTESTATION_RESPONSE.into(),
                attestation_protocol_version: SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3
                    .into(),
                binding_identity: format!("sha256:{}", "1".repeat(64)),
                challenge_nonce_commitment: format!("sha256:{}", "2".repeat(64)),
                invocation_id: String::from("systemd-invocation-1"),
                work_unit_identity: format!("sha256:{}", "3".repeat(64)),
                semantic_scope_identity: format!("sha256:{}", "4".repeat(64)),
                runner_principal: complete_v3.instance_v1.principal_mapping.identity.clone(),
                channel_delivery: String::from("launcher_session_fd"),
                authenticated_origin: String::from("systemd-protected-launcher"),
                authority_mounts: vec![String::from("authority-binding-v2")],
                systemd_protected_launcher: complete_v3,
                issuer: String::from("systemd-attestor"),
                audience: String::from("ota-crossing-broker"),
                issued_at: String::from("2026-08-08T00:00:00Z"),
                expires_at: String::from("2026-08-08T00:02:00Z"),
            },
            key_id: String::from("systemd-attestor-2026-01"),
            algorithm: String::from("ed25519"),
            signature: String::from("signature"),
        };
        assert!(launcher_attestation_identity_v3(&attestation).is_ok());
        let mut legacy_schema_attestation = attestation.clone();
        legacy_schema_attestation.payload.systemd_protected_launcher = legacy_complete;
        assert_eq!(
            launcher_attestation_identity_v3(&legacy_schema_attestation),
            Err(ProtocolError::InvalidRecord)
        );
        let mut legacy_profile_attestation = attestation.clone();
        let mut legacy_profile_in_v3 = complete.clone();
        legacy_profile_in_v3.schema_version = 3;
        legacy_profile_in_v3.identity = format!("sha256:{}", "5".repeat(64));
        for observation in &mut legacy_profile_in_v3.launcher_observations {
            observation.evidence_identity = Some(format!("sha256:{}", "6".repeat(64)));
        }
        for observation in &mut legacy_profile_in_v3.job_principal_observations {
            observation.evidence_identity = Some(format!("sha256:{}", "7".repeat(64)));
        }
        legacy_profile_attestation
            .payload
            .systemd_protected_launcher = legacy_profile_in_v3;
        assert_eq!(
            launcher_attestation_identity_v3(&legacy_profile_attestation),
            Err(ProtocolError::InvalidRecord)
        );
        let claims = launcher_attestation_claims_v3(&attestation);
        let claims_identity =
            launcher_attestation_claims_v3_identity(&claims).expect("claims identity");
        assert_ne!(
            claims_identity,
            launcher_attestation_identity_v3(&attestation).expect("attestation identity")
        );
        let challenge = BrokerChallenge {
            message_kind: CHALLENGE_REQUEST.into(),
            protocol_version: PROTOCOL_VERSION_V1.into(),
            binding_identity: claims.binding_identity.clone(),
            nonce_commitment: claims.challenge_nonce_commitment.clone(),
            work_unit_identity: claims.work_unit_identity.clone(),
            semantic_scope_identity: claims.semantic_scope_identity.clone(),
            contract_identity: format!("sha256:{}", "5".repeat(64)),
        };
        let mut signing_request = LauncherAttestationSigningRequestV1 {
            schema_version: 1,
            message_kind: LAUNCHER_ATTESTATION_SIGNING_REQUEST.into(),
            request_identity: String::new(),
            challenge,
            claims_identity: claims_identity.clone(),
            claims,
            launcher_service_binding_identity: format!("sha256:{}", "6".repeat(64)),
            launcher_configuration_identity: format!("sha256:{}", "7".repeat(64)),
            launcher_executable_identity: format!("sha256:{}", "8".repeat(64)),
            launcher_profile_identity: format!("sha256:{}", "9".repeat(64)),
            producer_binding_identity: format!("sha256:{}", "a".repeat(64)),
            producer_audience: String::from("ota-crossing-broker"),
            requested_maximum_validity_seconds: 120,
        };
        signing_request.request_identity =
            launcher_attestation_signing_request_v1_identity(&signing_request)
                .expect("signing request identity");
        validate_launcher_attestation_signing_request_v1(&signing_request)
            .expect("valid signing request");

        let mut signing_response = LauncherAttestationSigningResponseV1 {
            schema_version: 1,
            message_kind: LAUNCHER_ATTESTATION_SIGNING_RESPONSE.into(),
            request_identity: signing_request.request_identity.clone(),
            claims_identity,
            attestation: attestation.clone(),
            response_identity: String::new(),
        };
        signing_response.response_identity =
            launcher_attestation_signing_response_v1_identity(&signing_response)
                .expect("signing response identity");
        assert_eq!(
            signing_response.claims_identity,
            "sha256:740faa5f715d14be3d5230de93d94523cd7a7ed51d2f75bf73ee61998e1ccd9e"
        );
        assert_eq!(
            signing_request.request_identity,
            "sha256:d6031f445681de60286a7ff507222732af69d933d9be9a268dbe35a0df12bdb2"
        );
        assert_eq!(
            signing_response.response_identity,
            "sha256:bee2218cf17d8e26d3306389fe15efbb5151c93d25858a1a72d94fb1b39eff4d"
        );
        validate_launcher_attestation_signing_response_v1(&signing_response)
            .expect("valid signing response");

        let mut changed_claims = signing_request.clone();
        changed_claims
            .claims
            .authenticated_origin
            .push_str("-substituted");
        assert_eq!(
            validate_launcher_attestation_signing_request_v1(&changed_claims),
            Err(ProtocolError::InvalidRecord)
        );
        let mut changed_request = signing_response.clone();
        changed_request.request_identity = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            validate_launcher_attestation_signing_response_v1(&changed_request),
            Err(ProtocolError::InvalidRecord)
        );
        let mut changed_response_claims = signing_response.clone();
        changed_response_claims
            .attestation
            .payload
            .authenticated_origin
            .push_str("-substituted");
        assert_eq!(
            validate_launcher_attestation_signing_response_v1(&changed_response_claims),
            Err(ProtocolError::InvalidRecord)
        );
        let mut changed_protocol = attestation.clone();
        changed_protocol.payload.attestation_protocol_version =
            RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2.into();
        assert_eq!(
            launcher_attestation_identity_v3(&changed_protocol),
            Err(ProtocolError::InvalidRecord)
        );
        let mut missing = complete.clone();
        missing.launcher_observations.pop();
        assert_eq!(
            systemd_protected_launcher_instance_v2_identity(&missing),
            Err(ProtocolError::InvalidRecord)
        );
        let mut reordered = complete.clone();
        reordered.job_principal_observations.swap(0, 1);
        assert_eq!(
            systemd_protected_launcher_instance_v2_identity(&reordered),
            Err(ProtocolError::InvalidRecord)
        );
        let mut substituted = instance.clone();
        substituted.process_posture.principal_mapping_identity =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        assert_eq!(
            systemd_protected_launcher_instance_identity(&substituted),
            Err(ProtocolError::InvalidRecord)
        );
    }

    #[test]
    fn v2_attestation_has_a_distinct_wire_shape_and_identity_domain() {
        let profile = protected_launcher_profile_v1();
        let observations = profile
            .observations
            .iter()
            .map(|requirement| RuntimeBoundaryObservation {
                name: requirement.name,
                state: RuntimeBoundaryObservationState::Verified,
                evidence_method: requirement.evidence_method,
                reason_code: "verified_by_protected_launcher".into(),
                semantic_identity: (requirement.semantic_identity
                    == RuntimeBoundarySemanticIdentityPosture::Required)
                    .then(|| "sha256:bounded-measurement".into()),
            })
            .collect();
        let attestation = SignedLauncherAttestationV2 {
            payload: LauncherAttestationPayloadV2 {
                message_kind: ATTESTATION_RESPONSE.into(),
                attestation_protocol_version: RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2.into(),
                binding_identity: "sha256:binding-v2".into(),
                challenge_nonce_commitment: "sha256:nonce".into(),
                invocation_id: "invocation".into(),
                work_unit_identity: "sha256:work-unit".into(),
                semantic_scope_identity: "sha256:scope".into(),
                runner_principal: "ota-runner".into(),
                channel_delivery: "launcher_session_fd".into(),
                authenticated_origin: "protected_launcher".into(),
                authority_mounts: vec!["authority_binding".into(), "attestor_state".into()],
                runtime_boundary: RuntimeBoundaryAttestation {
                    schema_version: RUNTIME_BOUNDARY_SCHEMA_VERSION_V1,
                    profile_id: profile.profile_id.clone(),
                    profile_identity: runtime_boundary_profile_identity(&profile)
                        .expect("profile identity"),
                    attestor_kind: RuntimeBoundaryAttestorKind::ProtectedLauncher,
                    attestor_instance_identity: "sha256:attestor".into(),
                    launcher_session_binding_identity: "sha256:launcher-session".into(),
                    observations,
                },
                issuer: "runner-launcher".into(),
                audience: "ota-crossing-broker".into(),
                issued_at: "2026-08-08T00:00:00Z".into(),
                expires_at: "2026-08-08T00:02:00Z".into(),
            },
            key_id: "attestor-2026-01".into(),
            algorithm: "ed25519".into(),
            signature: "signature".into(),
        };

        let value = serde_json::to_value(&attestation).expect("v2 attestation JSON");
        assert_eq!(
            value["payload"]["attestation_protocol_version"],
            RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2
        );
        assert_eq!(
            value["payload"]["runtime_boundary"]["profile_id"],
            PROTECTED_LAUNCHER_PROFILE_ID_V1
        );
        assert_eq!(
            value["payload"]["runtime_boundary"]["observations"]
                .as_array()
                .expect("observations")
                .len(),
            11
        );
        assert_eq!(
            launcher_attestation_identity_v2(&attestation).expect("attestation identity"),
            "sha256:472aa0b63f6e9a056d4a546206aabbf0c80ddc0ff9be906b19722a4e17d29085"
        );

        assert!(serde_json::from_value::<SignedLauncherAttestation>(value.clone()).is_err());
        let v1 = serde_json::json!({
            "payload": {
                "message_kind": "attestation_response",
                "binding_identity": "binding",
                "challenge_nonce_commitment": "nonce",
                "invocation_id": "invocation",
                "work_unit_identity": "work",
                "semantic_scope_identity": "scope",
                "runner_principal": "runner",
                "channel_delivery": "launcher_session_fd",
                "authenticated_origin": "launcher",
                "authority_mounts": ["authority_binding"],
                "issuer": "issuer",
                "audience": "audience",
                "issued_at": "2026-08-08T00:00:00Z",
                "expires_at": "2026-08-08T00:02:00Z"
            },
            "key_id": "key",
            "algorithm": "ed25519",
            "signature": "signature"
        });
        assert!(serde_json::from_value::<SignedLauncherAttestationV2>(v1).is_err());
    }

    #[test]
    fn every_wire_type_has_a_stable_json_shape() {
        let challenge = BrokerChallenge {
            message_kind: CHALLENGE_REQUEST.into(),
            protocol_version: PROTOCOL_VERSION_V1.into(),
            binding_identity: "binding".into(),
            nonce_commitment: "nonce".into(),
            work_unit_identity: "work".into(),
            semantic_scope_identity: "scope".into(),
            contract_identity: "contract".into(),
        };
        assert_eq!(
            serde_json::to_value(&challenge).expect("challenge"),
            serde_json::json!({
                "message_kind": "challenge_request",
                "protocol_version": "ota-crossing-broker/v1",
                "binding_identity": "binding",
                "nonce_commitment": "nonce",
                "work_unit_identity": "work",
                "semantic_scope_identity": "scope",
                "contract_identity": "contract"
            })
        );

        let attestation = SignedLauncherAttestation {
            payload: LauncherAttestationPayload {
                message_kind: ATTESTATION_RESPONSE.into(),
                binding_identity: "binding".into(),
                challenge_nonce_commitment: "nonce".into(),
                invocation_id: "invocation".into(),
                work_unit_identity: "work".into(),
                semantic_scope_identity: "scope".into(),
                runner_principal: "runner".into(),
                channel_delivery: "launcher_session_fd".into(),
                authenticated_origin: "launcher".into(),
                authority_mounts: vec!["/etc/ota".into()],
                issuer: "issuer".into(),
                audience: "audience".into(),
                issued_at: "2026-08-05T00:00:00Z".into(),
                expires_at: "2026-08-05T00:02:00Z".into(),
            },
            key_id: "attestation-key".into(),
            algorithm: "ed25519".into(),
            signature: "signature".into(),
        };
        let authorization = AuthorizationRequest {
            message_kind: AUTHORIZATION_REQUEST.into(),
            binding_identity: "binding".into(),
            authority_id: "authority".into(),
            attestation_identity: "attestation".into(),
            challenge_nonce_commitment: "nonce".into(),
            work_unit_identity: "work".into(),
            contract_identity: "contract".into(),
            semantic_scope_identity: "scope".into(),
            runner_principal: "runner".into(),
            actor_mode: "non_agent".into(),
            requested_lifetime_seconds: 120,
        };
        let decision = SignedBrokerMessage {
            payload: AuthorizationDecisionPayload {
                message_kind: AUTHORIZATION_DECISION.into(),
                request_identity: "request".into(),
                binding_identity: "binding".into(),
                authority_id: "authority".into(),
                attestation_identity: "attestation".into(),
                challenge_nonce_commitment: "nonce".into(),
                work_unit_identity: "work".into(),
                contract_identity: "contract".into(),
                semantic_scope_identity: "scope".into(),
                decision: AuthorizationDecision::Allowed,
                approval_reference: Some("approval".into()),
                broker_revision: 7,
                issued_at: "2026-08-05T00:00:00Z".into(),
                expires_at: "2026-08-05T00:02:00Z".into(),
            },
            key_id: "broker-key".into(),
            algorithm: "ed25519".into(),
            signature: "signature".into(),
        };
        let lease = SignedBrokerMessage {
            payload: PreparedLeasePayload {
                message_kind: LEASE_ISSUANCE.into(),
                authorization_decision_identity: "decision".into(),
                binding_identity: "binding".into(),
                authority_id: "authority".into(),
                attestation_identity: "attestation".into(),
                challenge_nonce_commitment: "nonce".into(),
                work_unit_identity: "work".into(),
                contract_identity: "contract".into(),
                semantic_scope_identity: "scope".into(),
                runner_principal: "runner".into(),
                broker_revision: 7,
                lease_sequence: 9,
                issued_at: "2026-08-05T00:00:00Z".into(),
                expires_at: "2026-08-05T00:02:00Z".into(),
            },
            key_id: "broker-key".into(),
            algorithm: "ed25519".into(),
            signature: "signature".into(),
        };
        let consume = LeaseConsumeRequest {
            message_kind: LEASE_CONSUME.into(),
            binding_identity: "binding".into(),
            lease_identity: "lease".into(),
            challenge_nonce_commitment: "nonce".into(),
            work_unit_identity: "work".into(),
            crossing_transaction_id: "transaction-id".into(),
            crossing_transaction_identity: "transaction".into(),
        };
        let consumed = SignedBrokerMessage {
            payload: LeaseConsumeResponsePayload {
                message_kind: LEASE_CONSUME_RESPONSE.into(),
                consume_request_identity: "consume".into(),
                binding_identity: "binding".into(),
                lease_identity: "lease".into(),
                challenge_nonce_commitment: "nonce".into(),
                work_unit_identity: "work".into(),
                crossing_transaction_id: "transaction-id".into(),
                crossing_transaction_identity: "transaction".into(),
                state: LeaseConsumeState::Consumed,
                broker_revision: 8,
                consumed_at: "2026-08-05T00:00:30Z".into(),
            },
            key_id: "broker-key".into(),
            algorithm: "ed25519".into(),
            signature: "signature".into(),
        };

        for (kind, domain, value, expected_json, expected_identity) in [
            (
                CHALLENGE_REQUEST,
                CHALLENGE_REQUEST_DOMAIN_V1,
                serde_json::to_value(challenge).expect("challenge"),
                r#"{"binding_identity":"binding","contract_identity":"contract","message_kind":"challenge_request","nonce_commitment":"nonce","protocol_version":"ota-crossing-broker/v1","semantic_scope_identity":"scope","work_unit_identity":"work"}"#,
                "sha256:3503f9af4dbe3388487bba4c46ad163cae4c7f4da8efa7f8f4d9adb31c3214d1",
            ),
            (
                ATTESTATION_RESPONSE,
                ATTESTATION_RESPONSE_DOMAIN_V1,
                serde_json::to_value(attestation).expect("attestation"),
                r#"{"algorithm":"ed25519","key_id":"attestation-key","payload":{"audience":"audience","authenticated_origin":"launcher","authority_mounts":["/etc/ota"],"binding_identity":"binding","challenge_nonce_commitment":"nonce","channel_delivery":"launcher_session_fd","expires_at":"2026-08-05T00:02:00Z","invocation_id":"invocation","issued_at":"2026-08-05T00:00:00Z","issuer":"issuer","message_kind":"attestation_response","runner_principal":"runner","semantic_scope_identity":"scope","work_unit_identity":"work"},"signature":"signature"}"#,
                "sha256:cf6cd1f4e4a75ac1582a327fd2de83c75fd077814266c03e822d2414c6a4a1a4",
            ),
            (
                AUTHORIZATION_REQUEST,
                AUTHORIZATION_REQUEST_DOMAIN_V1,
                serde_json::to_value(authorization).expect("authorization"),
                r#"{"actor_mode":"non_agent","attestation_identity":"attestation","authority_id":"authority","binding_identity":"binding","challenge_nonce_commitment":"nonce","contract_identity":"contract","message_kind":"authorization_request","requested_lifetime_seconds":120,"runner_principal":"runner","semantic_scope_identity":"scope","work_unit_identity":"work"}"#,
                "sha256:3aadc8178d27f850975f9923b5bbf70f399a47dab1dbb5fe449182fb11d50a65",
            ),
            (
                AUTHORIZATION_DECISION,
                AUTHORIZATION_DECISION_DOMAIN_V1,
                serde_json::to_value(decision).expect("decision"),
                r#"{"algorithm":"ed25519","key_id":"broker-key","payload":{"approval_reference":"approval","attestation_identity":"attestation","authority_id":"authority","binding_identity":"binding","broker_revision":7,"challenge_nonce_commitment":"nonce","contract_identity":"contract","decision":"allowed","expires_at":"2026-08-05T00:02:00Z","issued_at":"2026-08-05T00:00:00Z","message_kind":"authorization_decision","request_identity":"request","semantic_scope_identity":"scope","work_unit_identity":"work"},"signature":"signature"}"#,
                "sha256:c5c63a0597808817d563e0542838cf339480ddfd8de7470e3be6a11900a9fff0",
            ),
            (
                LEASE_ISSUANCE,
                LEASE_ISSUANCE_DOMAIN_V1,
                serde_json::to_value(lease).expect("lease"),
                r#"{"algorithm":"ed25519","key_id":"broker-key","payload":{"attestation_identity":"attestation","authority_id":"authority","authorization_decision_identity":"decision","binding_identity":"binding","broker_revision":7,"challenge_nonce_commitment":"nonce","contract_identity":"contract","expires_at":"2026-08-05T00:02:00Z","issued_at":"2026-08-05T00:00:00Z","lease_sequence":9,"message_kind":"lease_issuance","runner_principal":"runner","semantic_scope_identity":"scope","work_unit_identity":"work"},"signature":"signature"}"#,
                "sha256:a40b879da59c7cc9dbb891aee5f88ec79afd219d57cdf40e7477317f4d11bba3",
            ),
            (
                LEASE_CONSUME,
                LEASE_CONSUME_DOMAIN_V1,
                serde_json::to_value(consume).expect("consume"),
                r#"{"binding_identity":"binding","challenge_nonce_commitment":"nonce","crossing_transaction_id":"transaction-id","crossing_transaction_identity":"transaction","lease_identity":"lease","message_kind":"lease_consume","work_unit_identity":"work"}"#,
                "sha256:24283d4438c471f303e6d0771adcdad54e1b850aa04ecf63f73bebcc50983471",
            ),
            (
                LEASE_CONSUME_RESPONSE,
                LEASE_CONSUME_RESPONSE_DOMAIN_V1,
                serde_json::to_value(consumed).expect("consumed"),
                r#"{"algorithm":"ed25519","key_id":"broker-key","payload":{"binding_identity":"binding","broker_revision":8,"challenge_nonce_commitment":"nonce","consume_request_identity":"consume","consumed_at":"2026-08-05T00:00:30Z","crossing_transaction_id":"transaction-id","crossing_transaction_identity":"transaction","lease_identity":"lease","message_kind":"lease_consume_response","state":"consumed","work_unit_identity":"work"},"signature":"signature"}"#,
                "sha256:a47e830b9d2ae523b990047fe1456171c4ddde8d20e760b645fe07530be6b524",
            ),
        ] {
            let observed = value
                .get("message_kind")
                .or_else(|| {
                    value
                        .get("payload")
                        .and_then(|payload| payload.get("message_kind"))
                })
                .and_then(serde_json::Value::as_str);
            assert_eq!(observed, Some(kind));
            let canonical = String::from_utf8(serde_jcs::to_vec(&value).expect("canonical wire"))
                .expect("UTF-8 wire");
            assert_eq!(canonical, expected_json, "{kind} canonical JSON drifted");
            assert_eq!(
                message_identity(domain.as_bytes(), &value).expect("wire identity"),
                expected_identity,
                "{kind} identity drifted"
            );
        }
    }

    #[test]
    fn consumption_recovery_wire_shapes_are_stable() {
        let query = LeaseConsumptionQuery {
            message_kind: LEASE_CONSUMPTION_QUERY.into(),
            binding_identity: "binding".into(),
            attestation_identity: "fresh-attestation".into(),
            recovery_challenge_nonce_commitment: "fresh-nonce".into(),
            recovery_work_unit_identity: "fresh-work".into(),
            lease_identity: "lease".into(),
            consume_request_identity: "consume".into(),
            original_work_unit_identity: "original-work".into(),
            crossing_transaction_id: "transaction-id".into(),
            crossing_transaction_identity: "transaction".into(),
        };
        let original_response = SignedBrokerMessage {
            payload: LeaseConsumeResponsePayload {
                message_kind: LEASE_CONSUME_RESPONSE.into(),
                consume_request_identity: "consume".into(),
                binding_identity: "binding".into(),
                lease_identity: "lease".into(),
                challenge_nonce_commitment: "original-nonce".into(),
                work_unit_identity: "original-work".into(),
                crossing_transaction_id: "transaction-id".into(),
                crossing_transaction_identity: "transaction".into(),
                state: LeaseConsumeState::Consumed,
                broker_revision: 8,
                consumed_at: "2026-08-05T00:00:30Z".into(),
            },
            key_id: "broker-key".into(),
            algorithm: "ed25519".into(),
            signature: "consume-signature".into(),
        };
        let status = SignedBrokerMessage {
            payload: LeaseConsumptionStatusPayload {
                message_kind: LEASE_CONSUMPTION_STATUS.into(),
                query_identity: "query".into(),
                binding_identity: "binding".into(),
                attestation_identity: "fresh-attestation".into(),
                recovery_challenge_nonce_commitment: "fresh-nonce".into(),
                recovery_work_unit_identity: "fresh-work".into(),
                lease_identity: "lease".into(),
                consume_request_identity: "consume".into(),
                original_work_unit_identity: "original-work".into(),
                crossing_transaction_id: "transaction-id".into(),
                crossing_transaction_identity: "transaction".into(),
                broker_revision: 9,
                observed_at: "2026-08-05T00:00:40Z".into(),
                status: LeaseConsumptionStatus::Consumed {
                    consume_response: Box::new(original_response),
                },
            },
            key_id: "broker-key".into(),
            algorithm: "ed25519".into(),
            signature: "status-signature".into(),
        };
        assert_eq!(
            message_identity(LEASE_CONSUMPTION_QUERY_DOMAIN_V1.as_bytes(), &query)
                .expect("query identity"),
            "sha256:dfa49f07ccf68bfb64b3fb788f3fa5914f88398476776a497ba6e60012c98833"
        );
        assert_eq!(
            signed_message_identity(LEASE_CONSUMPTION_STATUS_DOMAIN_V1.as_bytes(), &status)
                .expect("status identity"),
            "sha256:aca314f295c55eeafcb43c4a869824cdf3a47e32aa07ac0bb842f56da8e8dab7"
        );
        let consumed_json = serde_json::to_value(status).expect("consumed status JSON");
        assert_eq!(
            consumed_json
                .pointer("/payload/status/state")
                .and_then(serde_json::Value::as_str),
            Some("consumed")
        );
        assert!(
            consumed_json
                .pointer("/payload/status/consume_response")
                .is_some()
        );
    }
}
