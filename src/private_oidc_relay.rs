//                █████
//               ░░███
//       ██████  ███████    ██████
//      ███░░███░░░███░    ░░░░░███
//     ░███ ░███  ░███ ███ ███░░███
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

// Private, structural wire contract only. Session ownership and authority live in consumers.
use serde::{Deserialize, Serialize};

use crate::{
    ProtocolError, is_canonical_positive_decimal, is_canonical_workflow_reference,
    is_sha256_identity, message_identity,
};

pub const PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_REQUEST_V1: &str =
    "protected_github_oidc_capability_relay_request_v1";
pub const PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_CHALLENGE_V1: &str =
    "protected_github_oidc_capability_relay_challenge_v1";
pub const PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_ACKNOWLEDGEMENT_V1: &str =
    "protected_github_oidc_capability_relay_acknowledgement_v1";
pub const PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_REQUEST_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.protected-github-oidc-capability-relay-request.v1\0";
pub const MAX_PRIVATE_OIDC_RELAY_FRAME_PAYLOAD_BYTES_V1: usize = 16 * 1024;
pub const MAX_PRIVATE_OIDC_RELAY_URL_BYTES_V1: usize = 4096;
pub const MAX_PRIVATE_OIDC_RELAY_BEARER_BYTES_V1: usize = 8192;
const PRIVATE_OIDC_RELAY_MAGIC_V1: &[u8; 8] = b"OTAOIDC1";
const PRIVATE_OIDC_RELAY_HEADER_BYTES_V1: usize = 4 + 8 + 32 + 32 + 2 + 2;

/// Takes ownership of a credential input before building the one private frame.
pub struct ProtectedGithubOidcSecretInputV1(Vec<u8>);

impl ProtectedGithubOidcSecretInputV1 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for ProtectedGithubOidcSecretInputV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedGithubOidcSecretInputV1([redacted])")
    }
}

impl Drop for ProtectedGithubOidcSecretInputV1 {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedGithubOidcCapabilityRelayRequestV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub identity: String,
    pub launcher_request_identity: String,
    pub startup_continuation_identity: String,
    pub session_identity: String,
    pub protected_snapshot_identity: String,
    pub v4_binding_identity: String,
    pub observation_request_identity: String,
    pub transaction_candidate_identity: String,
    pub transport_dependency_record_identity: String,
    pub workflow_reference: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedGithubOidcCapabilityRelayChallengeV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: String,
    pub nonce: String,
    pub max_url_bytes: u32,
    pub max_bearer_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedGithubOidcCapabilityRelayAcknowledgementV1 {
    pub schema_version: u32,
    pub message_kind: String,
    pub request_identity: String,
    pub nonce: String,
    pub session_identity: String,
    pub v4_binding_identity: String,
}

#[derive(Serialize)]
struct RelayRequestIdentityInputV1<'a> {
    schema_version: u32,
    message_kind: &'a str,
    launcher_request_identity: &'a str,
    startup_continuation_identity: &'a str,
    session_identity: &'a str,
    protected_snapshot_identity: &'a str,
    v4_binding_identity: &'a str,
    observation_request_identity: &'a str,
    transaction_candidate_identity: &'a str,
    transport_dependency_record_identity: &'a str,
    workflow_reference: &'a str,
    workflow_run_id: &'a str,
    workflow_run_attempt: &'a str,
}

pub fn protected_github_oidc_capability_relay_request_v1_identity(
    request: &ProtectedGithubOidcCapabilityRelayRequestV1,
) -> Result<String, ProtocolError> {
    if request.schema_version != 1
        || request.message_kind != PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_REQUEST_V1
        || [
            &request.launcher_request_identity,
            &request.startup_continuation_identity,
            &request.session_identity,
            &request.protected_snapshot_identity,
            &request.v4_binding_identity,
            &request.observation_request_identity,
            &request.transaction_candidate_identity,
            &request.transport_dependency_record_identity,
        ]
        .into_iter()
        .any(|identity| !is_sha256_identity(identity))
        || !is_canonical_workflow_reference(&request.workflow_reference)
        || !is_canonical_positive_decimal(&request.workflow_run_id)
        || !is_canonical_positive_decimal(&request.workflow_run_attempt)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    message_identity(
        PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_REQUEST_IDENTITY_DOMAIN_V1,
        &RelayRequestIdentityInputV1 {
            schema_version: request.schema_version,
            message_kind: &request.message_kind,
            launcher_request_identity: &request.launcher_request_identity,
            startup_continuation_identity: &request.startup_continuation_identity,
            session_identity: &request.session_identity,
            protected_snapshot_identity: &request.protected_snapshot_identity,
            v4_binding_identity: &request.v4_binding_identity,
            observation_request_identity: &request.observation_request_identity,
            transaction_candidate_identity: &request.transaction_candidate_identity,
            transport_dependency_record_identity: &request.transport_dependency_record_identity,
            workflow_reference: &request.workflow_reference,
            workflow_run_id: &request.workflow_run_id,
            workflow_run_attempt: &request.workflow_run_attempt,
        },
    )
}

pub fn validate_protected_github_oidc_capability_relay_request_v1(
    request: &ProtectedGithubOidcCapabilityRelayRequestV1,
) -> Result<(), ProtocolError> {
    if request.identity != protected_github_oidc_capability_relay_request_v1_identity(request)? {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn validate_protected_github_oidc_capability_relay_challenge_v1(
    challenge: &ProtectedGithubOidcCapabilityRelayChallengeV1,
) -> Result<(), ProtocolError> {
    if challenge.schema_version != 1
        || challenge.message_kind != PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_CHALLENGE_V1
        || !is_sha256_identity(&challenge.request_identity)
        || !is_canonical_positive_decimal(&challenge.workflow_run_id)
        || !is_canonical_positive_decimal(&challenge.workflow_run_attempt)
        || decode_lower_hex_32(&challenge.nonce).is_none()
        || challenge.max_url_bytes != MAX_PRIVATE_OIDC_RELAY_URL_BYTES_V1 as u32
        || challenge.max_bearer_bytes != MAX_PRIVATE_OIDC_RELAY_BEARER_BYTES_V1 as u32
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

pub fn validate_protected_github_oidc_capability_relay_acknowledgement_v1(
    acknowledgement: &ProtectedGithubOidcCapabilityRelayAcknowledgementV1,
) -> Result<(), ProtocolError> {
    if acknowledgement.schema_version != 1
        || acknowledgement.message_kind != PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_ACKNOWLEDGEMENT_V1
        || !is_sha256_identity(&acknowledgement.request_identity)
        || decode_lower_hex_32(&acknowledgement.nonce).is_none()
        || !is_sha256_identity(&acknowledgement.session_identity)
        || !is_sha256_identity(&acknowledgement.v4_binding_identity)
    {
        return Err(ProtocolError::InvalidRecord);
    }
    Ok(())
}

/// Owns secret bytes through every partial read, including EOF or timeout before parsing.
pub struct ProtectedGithubOidcPrivateReceiveBufferV1 {
    bytes: Vec<u8>,
    filled: usize,
}

impl Default for ProtectedGithubOidcPrivateReceiveBufferV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectedGithubOidcPrivateReceiveBufferV1 {
    pub fn new() -> Self {
        Self {
            bytes: vec![0; 4],
            filled: 0,
        }
    }

    /// Read directly into this borrowed range; never stage input in an ordinary buffer.
    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.filled..]
    }

    pub fn record_read(&mut self, count: usize) -> Result<(), ProtocolError> {
        if count == 0 || count > self.bytes.len() - self.filled {
            return Err(ProtocolError::InvalidRecord);
        }
        self.filled += count;
        if self.filled == 4 && self.bytes.len() == 4 {
            let payload_len = u32::from_be_bytes(self.bytes[..4].try_into().unwrap()) as usize;
            if payload_len > MAX_PRIVATE_OIDC_RELAY_FRAME_PAYLOAD_BYTES_V1 {
                return Err(ProtocolError::FrameTooLarge);
            }
            if payload_len + 4 < PRIVATE_OIDC_RELAY_HEADER_BYTES_V1 {
                return Err(ProtocolError::InvalidRecord);
            }
            self.bytes.resize(payload_len + 4, 0);
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<ProtectedGithubOidcPrivateFrameV1, ProtocolError> {
        if self.filled != self.bytes.len() || self.bytes.len() == 4 {
            return Err(ProtocolError::IncompleteFrame);
        }
        ProtectedGithubOidcPrivateFrameV1::from_received_bytes(std::mem::take(&mut self.bytes))
    }
}

impl std::fmt::Debug for ProtectedGithubOidcPrivateReceiveBufferV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedGithubOidcPrivateReceiveBufferV1([redacted])")
    }
}

impl Drop for ProtectedGithubOidcPrivateReceiveBufferV1 {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Owns the validated frame through refusal or forwarding; never serialize it.
pub struct ProtectedGithubOidcPrivateFrameV1 {
    bytes: Vec<u8>,
    url_end: usize,
}

/// A structurally valid private frame whose request and nonce were consumed and matched.
pub struct CorrelatedProtectedGithubOidcPrivateFrameV1(ProtectedGithubOidcPrivateFrameV1);

pub fn build_protected_github_oidc_private_frame_v1(
    request_identity: &str,
    nonce: &str,
    url: ProtectedGithubOidcSecretInputV1,
    bearer: ProtectedGithubOidcSecretInputV1,
) -> Result<CorrelatedProtectedGithubOidcPrivateFrameV1, ProtocolError> {
    let digest = request_identity
        .strip_prefix("sha256:")
        .and_then(decode_lower_hex_32)
        .ok_or(ProtocolError::InvalidRecord)?;
    let nonce_bytes = decode_lower_hex_32(nonce).ok_or(ProtocolError::InvalidRecord)?;
    if !(1..=MAX_PRIVATE_OIDC_RELAY_URL_BYTES_V1).contains(&url.0.len())
        || !(1..=MAX_PRIVATE_OIDC_RELAY_BEARER_BYTES_V1).contains(&bearer.0.len())
    {
        return Err(ProtocolError::InvalidRecord);
    }
    let payload_len = PRIVATE_OIDC_RELAY_HEADER_BYTES_V1 - 4 + url.0.len() + bearer.0.len();
    let mut bytes = Vec::with_capacity(payload_len + 4);
    bytes.extend_from_slice(&(payload_len as u32).to_be_bytes());
    bytes.extend_from_slice(PRIVATE_OIDC_RELAY_MAGIC_V1);
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&nonce_bytes);
    bytes.extend_from_slice(&(url.0.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&(bearer.0.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&url.0);
    bytes.extend_from_slice(&bearer.0);
    ProtectedGithubOidcPrivateFrameV1::from_received_bytes(bytes)?
        .correlate(request_identity, nonce)
}

impl std::fmt::Debug for CorrelatedProtectedGithubOidcPrivateFrameV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CorrelatedProtectedGithubOidcPrivateFrameV1([redacted])")
    }
}

impl std::fmt::Debug for ProtectedGithubOidcPrivateFrameV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedGithubOidcPrivateFrameV1([redacted])")
    }
}

impl Drop for ProtectedGithubOidcPrivateFrameV1 {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

impl ProtectedGithubOidcPrivateFrameV1 {
    fn from_received_bytes(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        let mut frame = Self { bytes, url_end: 0 };
        if frame.bytes.len() < PRIVATE_OIDC_RELAY_HEADER_BYTES_V1 {
            return Err(ProtocolError::IncompleteFrame);
        }
        let payload_len = u32::from_be_bytes(frame.bytes[0..4].try_into().unwrap()) as usize;
        if payload_len > MAX_PRIVATE_OIDC_RELAY_FRAME_PAYLOAD_BYTES_V1 {
            return Err(ProtocolError::FrameTooLarge);
        }
        if payload_len + 4 != frame.bytes.len() {
            return Err(ProtocolError::InvalidRecord);
        }
        if &frame.bytes[4..12] != PRIVATE_OIDC_RELAY_MAGIC_V1 {
            return Err(ProtocolError::InvalidRecord);
        }
        let url_len = u16::from_be_bytes(frame.bytes[76..78].try_into().unwrap()) as usize;
        let bearer_len = u16::from_be_bytes(frame.bytes[78..80].try_into().unwrap()) as usize;
        if !(1..=MAX_PRIVATE_OIDC_RELAY_URL_BYTES_V1).contains(&url_len)
            || !(1..=MAX_PRIVATE_OIDC_RELAY_BEARER_BYTES_V1).contains(&bearer_len)
            || PRIVATE_OIDC_RELAY_HEADER_BYTES_V1 + url_len + bearer_len != frame.bytes.len()
        {
            return Err(ProtocolError::InvalidRecord);
        }
        frame.url_end = PRIVATE_OIDC_RELAY_HEADER_BYTES_V1 + url_len;
        let url =
            std::str::from_utf8(&frame.bytes[PRIVATE_OIDC_RELAY_HEADER_BYTES_V1..frame.url_end])
                .map_err(|_| ProtocolError::InvalidRecord)?;
        if url.bytes().any(|byte| byte.is_ascii_control())
            || std::str::from_utf8(&frame.bytes[frame.url_end..]).is_err()
            || frame.bytes[frame.url_end..]
                .iter()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ProtocolError::InvalidRecord);
        }
        Ok(frame)
    }

    pub fn correlate(
        self,
        request_identity: &str,
        nonce: &str,
    ) -> Result<CorrelatedProtectedGithubOidcPrivateFrameV1, ProtocolError> {
        let digest = request_identity
            .strip_prefix("sha256:")
            .and_then(decode_lower_hex_32)
            .ok_or(ProtocolError::InvalidRecord)?;
        let nonce = decode_lower_hex_32(nonce).ok_or(ProtocolError::InvalidRecord)?;
        if self.bytes[12..44] != digest || self.bytes[44..76] != nonce {
            return Err(ProtocolError::InvalidRecord);
        }
        Ok(CorrelatedProtectedGithubOidcPrivateFrameV1(self))
    }
}

impl CorrelatedProtectedGithubOidcPrivateFrameV1 {
    pub fn as_wire_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub fn url_bytes(&self) -> &[u8] {
        &self.0.bytes[PRIVATE_OIDC_RELAY_HEADER_BYTES_V1..self.0.url_end]
    }

    pub fn bearer_bytes(&self) -> &[u8] {
        &self.0.bytes[self.0.url_end..]
    }
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut decoded = [0; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        fn nibble(byte: u8) -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            }
        }
        decoded[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sha256_identity;

    fn request() -> ProtectedGithubOidcCapabilityRelayRequestV1 {
        let id = sha256_identity(b"fixture");
        let mut request = ProtectedGithubOidcCapabilityRelayRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_REQUEST_V1.into(),
            identity: String::new(),
            launcher_request_identity: id.clone(),
            startup_continuation_identity: id.clone(),
            session_identity: id.clone(),
            protected_snapshot_identity: id.clone(),
            v4_binding_identity: id.clone(),
            observation_request_identity: id.clone(),
            transaction_candidate_identity: id.clone(),
            transport_dependency_record_identity: id,
            workflow_reference: "ota-run/ota/.github/workflows/secret-delivery-oidc-endpoint-evidence.yml@refs/heads/1.6.29-implementation".into(),
            workflow_run_id: "36271452585".into(),
            workflow_run_attempt: "1".into(),
        };
        request.identity =
            protected_github_oidc_capability_relay_request_v1_identity(&request).unwrap();
        request
    }

    #[test]
    fn relay_control_records_are_closed_and_domain_separated() {
        let request = request();
        validate_protected_github_oidc_capability_relay_request_v1(&request).unwrap();
        let mut identity_free = serde_json::to_value(&request).unwrap();
        identity_free.as_object_mut().unwrap().remove("identity");
        assert_eq!(
            request.identity,
            message_identity(
                PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_REQUEST_IDENTITY_DOMAIN_V1,
                &identity_free
            )
            .unwrap()
        );
        assert_eq!(
            request.identity,
            "sha256:160409754d609ffbe607484c1a9840996fe91a472522bd024faebbf83dead573"
        );
        assert_ne!(request.identity, sha256_identity(b"fixture"));
        let mut changed = request.clone();
        changed.workflow_run_attempt = "2".into();
        assert!(validate_protected_github_oidc_capability_relay_request_v1(&changed).is_err());
        changed.workflow_run_attempt = "0".into();
        assert!(protected_github_oidc_capability_relay_request_v1_identity(&changed).is_err());
        changed = request.clone();
        changed.message_kind = "protected_authority_snapshot_request_v2".into();
        assert!(protected_github_oidc_capability_relay_request_v1_identity(&changed).is_err());
        let mut json = serde_json::to_value(&request).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("bearer".into(), "secret".into());
        assert!(
            serde_json::from_value::<ProtectedGithubOidcCapabilityRelayRequestV1>(json).is_err()
        );

        let challenge = ProtectedGithubOidcCapabilityRelayChallengeV1 {
            schema_version: 1,
            message_kind: PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_CHALLENGE_V1.into(),
            request_identity: request.identity.clone(),
            workflow_run_id: request.workflow_run_id.clone(),
            workflow_run_attempt: request.workflow_run_attempt.clone(),
            nonce: "cd".repeat(32),
            max_url_bytes: MAX_PRIVATE_OIDC_RELAY_URL_BYTES_V1 as u32,
            max_bearer_bytes: MAX_PRIVATE_OIDC_RELAY_BEARER_BYTES_V1 as u32,
        };
        validate_protected_github_oidc_capability_relay_challenge_v1(&challenge).unwrap();
        let mut changed = challenge.clone();
        changed.nonce = "CD".repeat(32);
        assert!(validate_protected_github_oidc_capability_relay_challenge_v1(&changed).is_err());
        changed = challenge.clone();
        changed.max_bearer_bytes += 1;
        assert!(validate_protected_github_oidc_capability_relay_challenge_v1(&changed).is_err());

        let acknowledgement = ProtectedGithubOidcCapabilityRelayAcknowledgementV1 {
            schema_version: 1,
            message_kind: PROTECTED_GITHUB_OIDC_CAPABILITY_RELAY_ACKNOWLEDGEMENT_V1.into(),
            request_identity: request.identity.clone(),
            nonce: challenge.nonce.clone(),
            session_identity: request.session_identity.clone(),
            v4_binding_identity: request.v4_binding_identity.clone(),
        };
        validate_protected_github_oidc_capability_relay_acknowledgement_v1(&acknowledgement)
            .unwrap();
        let mut changed = acknowledgement;
        changed.schema_version = 2;
        assert!(
            validate_protected_github_oidc_capability_relay_acknowledgement_v1(&changed).is_err()
        );
    }

    fn frame(url: &[u8], bearer: &[u8]) -> Vec<u8> {
        let payload_len = 8 + 32 + 32 + 2 + 2 + url.len() + bearer.len();
        let mut bytes = Vec::with_capacity(payload_len + 4);
        bytes.extend_from_slice(&(payload_len as u32).to_be_bytes());
        bytes.extend_from_slice(PRIVATE_OIDC_RELAY_MAGIC_V1);
        bytes.extend_from_slice(&[0xab; 32]);
        bytes.extend_from_slice(&[0xcd; 32]);
        bytes.extend_from_slice(&(url.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(bearer.len() as u16).to_be_bytes());
        bytes.extend_from_slice(url);
        bytes.extend_from_slice(bearer);
        bytes
    }

    #[test]
    fn private_frame_is_bounded_correlated_and_redacted() {
        let url = b"https://token.actions.githubusercontent.com/request";
        let input = frame(url, b"secret");
        let mut receive = ProtectedGithubOidcPrivateReceiveBufferV1::new();
        receive.unfilled_mut().copy_from_slice(&input[..4]);
        receive.record_read(4).unwrap();
        receive.unfilled_mut().copy_from_slice(&input[4..]);
        receive.record_read(input.len() - 4).unwrap();
        let frame = receive
            .finish()
            .unwrap()
            .correlate(&format!("sha256:{}", "ab".repeat(32)), &"cd".repeat(32))
            .unwrap();
        assert_eq!(frame.url_bytes(), url);
        assert_eq!(frame.bearer_bytes(), b"secret");
        assert_eq!(frame.as_wire_bytes().len(), 80 + url.len() + 6);
        assert!(!format!("{frame:?}").contains("secret"));
        assert!(
            ProtectedGithubOidcPrivateFrameV1::from_received_bytes(input.clone())
                .unwrap()
                .correlate(&format!("sha256:{}", "ab".repeat(32)), &"ce".repeat(32))
                .is_err()
        );
        assert!(
            ProtectedGithubOidcPrivateFrameV1::from_received_bytes(input)
                .unwrap()
                .correlate(&format!("sha256:{}", "AB".repeat(32)), &"cd".repeat(32))
                .is_err()
        );
    }

    #[test]
    fn private_sender_and_receiver_share_exact_wire_bytes() {
        let request_identity = format!("sha256:{}", "ab".repeat(32));
        let nonce = "cd".repeat(32);
        let url = b"https://example.invalid/id-token";
        let bearer = b"private-bearer";
        let built = build_protected_github_oidc_private_frame_v1(
            &request_identity,
            &nonce,
            ProtectedGithubOidcSecretInputV1::new(url.to_vec()),
            ProtectedGithubOidcSecretInputV1::new(bearer.to_vec()),
        )
        .unwrap();
        assert_eq!(built.as_wire_bytes(), frame(url, bearer));
        assert!(!format!("{built:?}").contains("private-bearer"));
        let mut receive = ProtectedGithubOidcPrivateReceiveBufferV1::new();
        receive
            .unfilled_mut()
            .copy_from_slice(&built.as_wire_bytes()[..4]);
        receive.record_read(4).unwrap();
        receive
            .unfilled_mut()
            .copy_from_slice(&built.as_wire_bytes()[4..]);
        receive
            .record_read(built.as_wire_bytes().len() - 4)
            .unwrap();
        let received = receive
            .finish()
            .unwrap()
            .correlate(&request_identity, &nonce)
            .unwrap();
        assert_eq!(received.url_bytes(), url);
        assert_eq!(received.bearer_bytes(), bearer);

        assert!(
            build_protected_github_oidc_private_frame_v1(
                &request_identity,
                &nonce,
                ProtectedGithubOidcSecretInputV1::new(url.to_vec()),
                ProtectedGithubOidcSecretInputV1::new(b"bad\nvalue".to_vec()),
            )
            .is_err()
        );
        assert!(
            build_protected_github_oidc_private_frame_v1(
                "sha256:INVALID",
                &nonce,
                ProtectedGithubOidcSecretInputV1::new(url.to_vec()),
                ProtectedGithubOidcSecretInputV1::new(bearer.to_vec()),
            )
            .is_err()
        );
    }

    #[test]
    fn private_frame_refuses_alternate_and_malformed_shapes() {
        let valid = frame(b"https://example.invalid", b"bearer");
        for changed in [
            valid[..79].to_vec(),
            [valid.as_slice(), b"x"].concat(),
            {
                let mut bytes = valid.clone();
                bytes[4] = b'X';
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes[0..4].copy_from_slice(&(16385u32).to_be_bytes());
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes[76..78].copy_from_slice(&0u16.to_be_bytes());
                bytes
            },
            frame(b"\xff", b"bearer"),
            frame(b"https://example.invalid", b"bad\nvalue"),
            frame(b"https://example.invalid", b"\xff"),
        ] {
            assert!(ProtectedGithubOidcPrivateFrameV1::from_received_bytes(changed).is_err());
        }
        assert!(
            ProtectedGithubOidcPrivateFrameV1::from_received_bytes(frame(
                &vec![b'x'; MAX_PRIVATE_OIDC_RELAY_URL_BYTES_V1 + 1],
                b"bearer"
            ))
            .is_err()
        );
        assert!(
            ProtectedGithubOidcPrivateFrameV1::from_received_bytes(frame(
                b"https://example.invalid",
                &vec![b'x'; MAX_PRIVATE_OIDC_RELAY_BEARER_BYTES_V1 + 1],
            ))
            .is_err()
        );
        ProtectedGithubOidcPrivateFrameV1::from_received_bytes(frame(
            &vec![b'x'; MAX_PRIVATE_OIDC_RELAY_URL_BYTES_V1],
            &vec![b'y'; MAX_PRIVATE_OIDC_RELAY_BEARER_BYTES_V1],
        ))
        .unwrap();
    }

    #[test]
    fn partial_private_reads_remain_owned_and_incomplete() {
        let input = frame(b"https://example.invalid", b"secret");
        let mut receive = ProtectedGithubOidcPrivateReceiveBufferV1::new();
        receive.unfilled_mut()[..2].copy_from_slice(&input[..2]);
        receive.record_read(2).unwrap();
        assert_eq!(receive.unfilled_mut().len(), 2);
        assert_eq!(
            receive.finish().unwrap_err(),
            ProtocolError::IncompleteFrame
        );

        let mut receive = ProtectedGithubOidcPrivateReceiveBufferV1::new();
        receive.unfilled_mut().copy_from_slice(&input[..4]);
        receive.record_read(4).unwrap();
        receive.unfilled_mut()[..11].copy_from_slice(&input[4..15]);
        receive.record_read(11).unwrap();
        assert!(!format!("{receive:?}").contains("secret"));
        assert_eq!(
            receive.finish().unwrap_err(),
            ProtocolError::IncompleteFrame
        );

        let mut receive = ProtectedGithubOidcPrivateReceiveBufferV1::new();
        receive
            .unfilled_mut()
            .copy_from_slice(&(16385u32).to_be_bytes());
        assert_eq!(receive.record_read(4), Err(ProtocolError::FrameTooLarge));
    }
}
