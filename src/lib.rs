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
pub const RUNTIME_BOUNDARY_SCHEMA_VERSION_V1: u32 = 1;
pub const PROTECTED_LAUNCHER_PROFILE_ID_V1: &str = "ota.runtime-boundary.protected-launcher/v1";
pub const PROTECTED_LAUNCHER_IMAGE_PROFILE_ID_V1: &str =
    "ota.runtime-boundary.protected-launcher-image/v1";
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

pub const CHALLENGE_REQUEST: &str = "challenge_request";
pub const ATTESTATION_RESPONSE: &str = "attestation_response";
pub const AUTHORIZATION_REQUEST: &str = "authorization_request";
pub const AUTHORIZATION_DECISION: &str = "authorization_decision";
pub const LEASE_ISSUANCE: &str = "lease_issuance";
pub const LEASE_CONSUME: &str = "lease_consume";
pub const LEASE_CONSUME_RESPONSE: &str = "lease_consume_response";
pub const LEASE_CONSUMPTION_QUERY: &str = "lease_consumption_query";
pub const LEASE_CONSUMPTION_STATUS: &str = "lease_consumption_status";

pub const CHALLENGE_IDENTITY_DOMAIN_V1: &[u8] = b"ota.crossing-broker.challenge.v1\0";
pub const WORK_UNIT_IDENTITY_DOMAIN_V1: &[u8] = b"ota.crossing-broker.work-unit.v1\0";
pub const BROKER_BINDING_IDENTITY_DOMAIN_V1: &[u8] = b"ota.crossing-broker.binding.v1\0";
pub const BROKER_BINDING_IDENTITY_DOMAIN_V2: &[u8] = b"ota.crossing-broker.binding.v2\0";
pub const ATTESTATION_IDENTITY_DOMAIN_V2: &[u8] = b"ota.crossing-broker.attestation.v2\0";
pub const RUNTIME_BOUNDARY_PROFILE_IDENTITY_DOMAIN_V1: &[u8] = b"ota.runtime-boundary.profile.v1\0";
pub const CHALLENGE_REQUEST_DOMAIN_V1: &str = "ota-crossing-broker/challenge-request/v1";
pub const ATTESTATION_RESPONSE_DOMAIN_V1: &str = "ota-crossing-broker/attestation-response/v1";
pub const ATTESTATION_RESPONSE_DOMAIN_V2: &str = "ota-crossing-broker/attestation-response/v2";
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
