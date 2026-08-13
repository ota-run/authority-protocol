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
pub const SYSTEMD_LAUNCHER_PROFILE_ID_V1: &str = "ota.authority-launcher.systemd/v1";
pub const SYSTEMD_LAUNCHER_PROFILE_ID_V2: &str = "ota.authority-launcher.systemd/v2";
pub const SYSTEMD_LAUNCHER_PROFILE_ID_V3: &str = "ota.authority-launcher.systemd/v3";
pub const SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1: &str = "ota.authority-job-principal.systemd/v1";
pub const SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2: &str = "ota.authority-job-principal.systemd/v2";
pub const SYSTEMD_ATTESTOR_SOCKET_PATH_V1: &str = "/run/ota/authority-attestor.sock";
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
        || !is_absolute_bounded_path(scope.control_group.as_str(), 1024)
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
                && frame.exit_code == finalization.observed_exit_code
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
                && frame.exit_code == finalization.observed_exit_code
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
