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
pub const SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1: &str = "ota.authority-job-principal.systemd/v1";
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
pub const LEASE_ISSUANCE: &str = "lease_issuance";
pub const LEASE_CONSUME: &str = "lease_consume";
pub const LEASE_CONSUME_RESPONSE: &str = "lease_consume_response";
pub const LEASE_CONSUMPTION_QUERY: &str = "lease_consumption_query";
pub const LEASE_CONSUMPTION_STATUS: &str = "lease_consumption_status";
pub const LAUNCHER_INVOCATION_REQUEST: &str = "launcher_invocation_request";
pub const LAUNCHER_OUTPUT: &str = "launcher_output";
pub const LAUNCHER_TERMINAL: &str = "launcher_terminal";

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
    BoundaryFailed,
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

/// Complete systemd protected-launcher evidence. V1 remains the immutable identity foundation;
/// V2 adds the closed profile observations required for a production attestation.
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdJobPrincipalObservation {
    pub requirement: SystemdJobPrincipalRequirement,
    pub evidence_methods: Vec<SystemdJobPrincipalEvidenceMethod>,
    pub state: RuntimeBoundaryObservationState,
    pub reason_code: String,
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
    if frame.message_kind != LAUNCHER_TERMINAL
        || frame.protocol_version != SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1
        || !is_bounded_label(&frame.invocation_id, MAX_LAUNCHER_INVOCATION_ID_BYTES_V1)
        || matches!(frame.outcome, LauncherTerminalOutcomeV1::Completed)
            && frame.exit_code != Some(0)
        || matches!(frame.outcome, LauncherTerminalOutcomeV1::Cancelled)
            && frame.exit_code.is_some()
        || matches!(
            frame.stage,
            Some(
                LauncherTerminalStageV1::RequestRefusedBeforeBoundary
                    | LauncherTerminalStageV1::PostureAdmittedBoundaryRemoved
            )
        ) && (frame.outcome != LauncherTerminalOutcomeV1::Refused || frame.exit_code != Some(2))
        || matches!(frame.stage, Some(LauncherTerminalStageV1::BoundaryFailed))
            && (frame.outcome != LauncherTerminalOutcomeV1::Failed || frame.exit_code != Some(1))
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
        || systemd_protected_launcher_instance_v2_identity(
            &attestation.payload.systemd_protected_launcher,
        )? != attestation.payload.systemd_protected_launcher.identity
    {
        return Err(ProtocolError::InvalidRecord);
    }
    message_identity(ATTESTATION_IDENTITY_DOMAIN_V3, attestation)
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
    message_identity(SYSTEMD_LAUNCHER_INSTANCE_IDENTITY_DOMAIN_V2, &canonical)
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
    let mapping_identity = launcher_principal_mapping_identity(&instance.principal_mapping)?;
    let posture_identity = ota_process_posture_identity(&instance.process_posture)?;
    let launcher_profile_identity =
        systemd_launcher_profile_identity(&systemd_launcher_profile_v1())?;
    let job_profile_identity =
        systemd_job_principal_profile_identity(&systemd_job_principal_profile_v1())?;
    if instance.schema_version != 1
        || instance.adapter != SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1
        || instance.principal_mapping.identity != mapping_identity
        || instance.process_posture.identity != posture_identity
        || instance.process_posture.principal_mapping_identity != mapping_identity
        || instance.systemd_launcher_profile_identity != launcher_profile_identity
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
    validate_systemd_protected_launcher_instance_v1(&instance.instance_v1)?;
    if instance.instance_v1.identity
        != systemd_protected_launcher_instance_identity(&instance.instance_v1)?
        || instance.schema_version != 2
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let launcher_profile = systemd_launcher_profile_v1();
    if instance.launcher_observations.len() != launcher_profile.evidence_sources.len()
        || instance
            .launcher_observations
            .iter()
            .zip(launcher_profile.evidence_sources.iter())
            .any(|(observed, required)| {
                observed.source != *required
                    || observed.state != RuntimeBoundaryObservationState::Verified
                    || !is_reason_code(&observed.reason_code)
            })
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let job_profile = systemd_job_principal_profile_v1();
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
            })
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
        };
        assert_eq!(validate_launcher_terminal_frame_v1(&complete), Ok(()));

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
        };
        assert_eq!(
            validate_launcher_terminal_frame_v1(&posture_terminal),
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
        let principal = systemd_job_principal_profile_v1();

        assert_eq!(launcher.schema_version, 1);
        assert_eq!(launcher.profile_id, SYSTEMD_LAUNCHER_PROFILE_ID_V1);
        assert_eq!(launcher.service_settings.len(), 29);
        assert_eq!(launcher.socket_settings.len(), 7);
        assert_eq!(launcher.invocation_scope_settings.len(), 5);
        assert_eq!(launcher.evidence_sources.len(), 8);
        assert_eq!(principal.schema_version, 1);
        assert_eq!(principal.profile_id, SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V1);
        assert_eq!(principal.requirements.len(), 18);

        let launcher_identity =
            systemd_launcher_profile_identity(&launcher).expect("launcher profile identity");
        let principal_identity = systemd_job_principal_profile_identity(&principal)
            .expect("job principal profile identity");
        assert_eq!(
            launcher_identity,
            "sha256:32c49f19799e065d341c900a4ce0d7756669c0c0d4e990ffe81bbcda06291930"
        );
        assert_eq!(
            principal_identity,
            "sha256:e69ef375070bbb4f5616ba46b6f29b9a987372909016d1a1dfa40a5d4daae93d"
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
                runner_principal: complete.instance_v1.principal_mapping.identity.clone(),
                channel_delivery: String::from("launcher_session_fd"),
                authenticated_origin: String::from("systemd-protected-launcher"),
                authority_mounts: vec![String::from("authority-binding-v2")],
                systemd_protected_launcher: complete.clone(),
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
