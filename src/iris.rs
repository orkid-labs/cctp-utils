use anyhow::{anyhow, Result};
use hex::FromHex;
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use reqwest::Client;
use serde::Deserialize;
use serde_json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct IrisResponse {
    status: String,
    attestation: Option<String>,
}

/// Poll Circle Iris API for attestation completion
pub async fn poll_iris_attestation(
    client: &Client,
    base_url: &str,
    message_hash: &str,
    timeout: Duration,
) -> Result<Option<String>> {
    let url = format!("{}/{}", base_url.trim_end_matches('/'), message_hash);
    let mut elapsed = Duration::from_secs(0);
    let interval = Duration::from_secs(2);
    while elapsed < timeout {
        let res = client.get(&url).send().await?;
        if res.status().is_success() {
            let body: IrisResponse = res.json().await?;
            if body.status == "complete" {
                return Ok(body.attestation);
            }
        }
        tokio::time::sleep(interval).await;
        elapsed += interval;
    }
    Ok(None)
}

/// Verify attestation timestamp freshness
pub fn verify_attestation_freshness(att_timestamp_secs: u64, max_latency_secs: u64) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if now < att_timestamp_secs {
        return Err(anyhow!("Attestation timestamp is in the future"));
    }
    if now - att_timestamp_secs > max_latency_secs {
        return Err(anyhow!("Attestation is stale"));
    }
    Ok(())
}

/// Verify an ECDSA signature over the provided message (hex signature expected)
pub fn verify_ecdsa_signature(
    message: &[u8],
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<bool> {
    let pk_bytes = <Vec<u8> as FromHex>::from_hex(public_key_hex)?;
    let sig_bytes = <Vec<u8> as FromHex>::from_hex(signature_hex)?;
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes.as_slice())?;
    let sig = Signature::from_der(sig_bytes.as_slice())?;
    match vk.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(e) => Err(anyhow!("signature verify failed: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct AttestationPayload {
    #[serde(alias = "message")]
    message: String,
    #[serde(alias = "signature")]
    signature: String,
    #[serde(alias = "signer_pubkey", alias = "signer", alias = "public_key")]
    signer_pubkey: Option<String>,
    #[serde(alias = "timestamp")]
    timestamp: Option<u64>,
}

/// Parse a Circle Iris attestation JSON string and verify signature + freshness.
/// The attestation JSON should contain at least `message` and `signature` fields.
/// Prefer `signer_pubkey` or `signer` to supply the public key in hex (SEC1 uncompressed).
pub fn parse_and_verify_attestation(attestation_json: &str, max_latency_secs: u64) -> Result<bool> {
    let payload: AttestationPayload = serde_json::from_str(attestation_json)?;

    // Determine message bytes: if message starts with 0x treat as hex, otherwise raw bytes
    let message_bytes: Vec<u8> = if payload.message.starts_with("0x") {
        // strip 0x
        let hexstr = payload.message.trim_start_matches("0x");
        <Vec<u8> as FromHex>::from_hex(hexstr)?
    } else {
        payload.message.as_bytes().to_vec()
    };

    // Signature must be present
    let signature_hex = payload.signature;

    // Public key must be provided in attestation JSON for offline verification
    let pk_hex = match payload.signer_pubkey.as_ref() {
        Some(pk) => pk.clone(),
        None => return Err(anyhow!("attestation missing signer public key")),
    };

    // Verify freshness if timestamp present
    if let Some(ts) = payload.timestamp {
        verify_attestation_freshness(ts, max_latency_secs)?;
    }

    let ok = verify_ecdsa_signature(&message_bytes, &pk_hex, &signature_hex)?;
    Ok(ok)
}

#[cfg(test)]
mod sig_tests {
    use super::*;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn test_sign_and_verify() {
        // generate random signing key
        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let msg = b"hello world";
        let sig: Signature = sk.sign(msg);
        let pk_hex = hex::encode(vk.to_encoded_point(false).as_bytes());
        let sig_der = sig.to_der();
        let sig_hex = hex::encode(sig_der.as_bytes());
        let ok = verify_ecdsa_signature(msg, &pk_hex, &sig_hex).unwrap();
        assert!(ok);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[tokio::test]
    async fn test_poll_iris_none() {
        let client = Client::new();
        let res = poll_iris_attestation(
            &client,
            "https://iris-api.circle.com/v1/attestations",
            "nonexistent",
            Duration::from_secs(1),
        )
        .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_poll_iris_mock_complete() {
        // spin up a mock server and ensure poller returns attestation
        let server = httpmock::MockServer::start_async().await;
        let message_hash = "abcd1234";
        let url_path = format!("/v1/attestations/{}", message_hash);
        let _m = server.mock_async(|when, then| {
            when.method(GET).path(url_path.as_str());
            then.status(200).json_body_obj(&serde_json::json!({"status":"complete","attestation":"{\"message\":\"0xdead\",\"signature\":\"00\"}"}));
        }).await;

        let client = Client::new();
        let base = server.url("/v1/attestations");
        let res = poll_iris_attestation(&client, &base, message_hash, Duration::from_secs(2)).await;
        assert!(res.is_ok());
        let att = res.unwrap();
        assert!(att.is_some());
    }

    #[test]
    fn test_verify_attestation_freshness_ok() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_attestation_freshness(now - 1, 60).is_ok());
    }

    #[test]
    fn test_verify_attestation_freshness_stale() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let res = verify_attestation_freshness(now - 3600, 30);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_and_verify_attestation_valid_hex_message() {
        // generate key
        let sk = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();

        // message as hex ("hello")
        let msg = b"hello";
        let msg_hex = format!("0x{}", hex::encode(msg));

        // sign
        let sig: Signature = sk.sign(msg);
        let sig_hex = hex::encode(sig.to_der().as_bytes());

        let pk_hex = hex::encode(vk.to_encoded_point(false).as_bytes());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json = serde_json::json!({
            "message": msg_hex,
            "signature": sig_hex,
            "signer_pubkey": pk_hex,
            "timestamp": ts,
        });

        let s = json.to_string();
        let ok = parse_and_verify_attestation(&s, 60).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_parse_and_verify_attestation_missing_pubkey() {
        let sk = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let msg = b"hello world";
        let msg_hex = format!("0x{}", hex::encode(msg));
        let sig: Signature = sk.sign(msg);
        let sig_hex = hex::encode(sig.to_der().as_bytes());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json = serde_json::json!({
            "message": msg_hex,
            "signature": sig_hex,
            "timestamp": ts
        });
        let s = json.to_string();
        let res = parse_and_verify_attestation(&s, 60);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_and_verify_attestation_stale_timestamp() {
        let sk = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let msg = b"time-sensitive";
        let msg_hex = format!("0x{}", hex::encode(msg));
        let sig: Signature = sk.sign(msg);
        let sig_hex = hex::encode(sig.to_der().as_bytes());
        let pk_hex = hex::encode(vk.to_encoded_point(false).as_bytes());

        // stale timestamp far in the past
        let ts = 1u64; // epoch

        let json = serde_json::json!({
            "message": msg_hex,
            "signature": sig_hex,
            "signer_pubkey": pk_hex,
            "timestamp": ts,
        });
        let s = json.to_string();
        let res = parse_and_verify_attestation(&s, 60);
        assert!(res.is_err());
    }
}
