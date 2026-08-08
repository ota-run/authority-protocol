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
pub const CHALLENGE_REQUEST_DOMAIN_V1: &str = "ota-crossing-broker/challenge-request/v1";
pub const ATTESTATION_RESPONSE_DOMAIN_V1: &str = "ota-crossing-broker/attestation-response/v1";
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
