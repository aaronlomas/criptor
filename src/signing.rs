//! Asymmetric cryptography: X.509 / PKCS#12 parsing and RSA-SHA256 signing.
//!
//! This module is a **pure cryptographic utility layer**: it has no dependency on the
//! vault database, the master key, or any engine state. It is designed to be consumed
//! directly by applications that need XMLDSIG signing (e.g. SUNAT electronic invoicing
//! in Peru) without instantiating a vault.
//!
//! Three building blocks:
//! - [`parse_pkcs12`]: extract an X.509 certificate + private key from a `.p12`/`.pfx`.
//! - [`parse_certificate_info`]: extract XMLDSIG fields from a PEM certificate.
//! - [`sign_hash_with_key`]: sign a SHA-256 digest with RSA-PKCS1v15.

use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::Certificate;

use crate::crypto::secret::SecretString;
use crate::error::CriptorError;

/// X.509 certificate fields required by XMLDSIG.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Base64-encoded DER certificate — injects into `<ds:X509Certificate>`.
    pub x509_base64: String,
    /// Issuer Distinguished Name — injects into `<ds:X509IssuerName>`.
    pub issuer_dn: String,
    /// Certificate serial number as a decimal string — injects into `<ds:X509SerialNumber>`.
    pub serial_number: String,
    /// Certificate validity start (Unix timestamp UTC).
    pub not_before: i64,
    /// Certificate validity end (Unix timestamp UTC).
    pub not_after: i64,
}

impl CertificateInfo {
    /// Returns `true` if the certificate is currently within its validity window.
    /// SUNAT rejects comprobantes signed with expired certificates.
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.not_before && now <= self.not_after
    }
}

/// Parses a PEM-encoded X.509 certificate and extracts data required for XMLDSIG.
///
/// This is a pure cryptographic utility that does not depend on the vault database.
/// The `pem_content` must contain a valid PEM-encoded certificate (`-----BEGIN CERTIFICATE-----`).
pub fn parse_certificate_info(pem_content: &str) -> Result<CertificateInfo, CriptorError> {
    let cert = Certificate::from_pem(pem_content.as_bytes())
        .map_err(|e| CriptorError::CryptoError(format!("Failed to parse X.509 certificate: {}", e)))?;

    build_certificate_info(&cert)
}

/// Parses a PKCS#12 (.pfx / .p12) file and returns both the `CertificateInfo` and
/// the private key as a `SecretString` (PEM-encoded).
///
/// In Peru, virtually all PSEs (Proveedores de Servicios Electrónicos) and certificate
/// authorities deliver credentials in `.p12` / `.pfx` format with a password. This function
/// eliminates the need for the caller to perform the conversion via OpenSSL.
///
/// # Security
/// The returned private key is wrapped in a [`SecretString`], so its bytes are zeroized
/// from memory as soon as it is dropped.
pub fn parse_pkcs12(
    p12_bytes: &[u8],
    password: &str,
) -> Result<(CertificateInfo, SecretString), CriptorError> {
    use openssl::pkcs12::Pkcs12;

    let pfx = Pkcs12::from_der(p12_bytes)
        .map_err(|e| CriptorError::Pkcs12Error(format!("Failed to parse PKCS12 file: {}", e)))?;

    let parsed = pfx
        .parse2(password)
        .map_err(|e| CriptorError::Pkcs12Error(format!("Failed to decrypt PKCS12 (check password): {}", e)))?;

    let key = parsed
        .pkey
        .ok_or_else(|| CriptorError::Pkcs12Error("No private key found in PKCS12 file".to_string()))?;
    // We use PKCS8 format for the private key PEM output
    let key_pem_bytes = key
        .private_key_to_pem_pkcs8()
        .map_err(|e| CriptorError::Pkcs12Error(format!("Failed to export private key to PEM: {}", e)))?;
    let key_pem = String::from_utf8(key_pem_bytes)
        .map_err(|e| CriptorError::Pkcs12Error(format!("Invalid UTF-8 in private key PEM: {}", e)))?;
    let private_key = SecretString::new(key_pem);

    let cert_openssl = parsed
        .cert
        .ok_or_else(|| CriptorError::Pkcs12Error("No certificate found in PKCS12 file".to_string()))?;
    let cert_der = cert_openssl
        .to_der()
        .map_err(|e| CriptorError::Pkcs12Error(format!("Failed to export certificate to DER: {}", e)))?;

    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| CriptorError::CryptoError(format!("Failed to parse certificate from PKCS12: {}", e)))?;

    let cert_info = build_certificate_info(&cert)?;

    Ok((cert_info, private_key))
}

/// Signs a 32-byte SHA-256 hash using a PEM-encoded RSA private key.
///
/// This is a pure cryptographic utility that does not depend on the vault database.
///
/// # Security
/// The `pem_private_key` is accepted as a [`SecretString`] to guarantee that
/// the key bytes are zeroized from memory (overwritten with 0x00) as soon as
/// this call returns, preventing residual key material from being found in a
/// memory dump or core dump.
///
/// # Key format
/// Supports both PKCS#8 (`-----BEGIN PRIVATE KEY-----`) and
/// PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) formats.
///
/// # Returns
/// The RSA-SHA256/PKCS1v15 signature encoded in Base64, ready to inject
/// into `<ds:SignatureValue>` in an XMLDSIG structure.
pub fn sign_hash_with_key(
    pem_private_key: &SecretString,
    hash: &[u8; 32],
) -> Result<String, CriptorError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::Sha256;
    use rsa::RsaPrivateKey;

    let pem = pem_private_key.as_str();

    // Attempt PKCS#8 first, then fallback to PKCS#1.
    // Both formats are common depending on the issuing CA.
    let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|_| CriptorError::InvalidKeyFormat)?;

    // Sign the hash using PKCS#1 v1.5 with SHA-256 (required by SUNAT XMLDSIG).
    let padding = Pkcs1v15Sign::new::<Sha256>();
    let signature = private_key
        .sign(padding, hash)
        .map_err(|e| CriptorError::CryptoError(format!("Cryptographic signing failed: {}", e)))?;

    Ok(general_purpose::STANDARD.encode(signature))
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Builds a `CertificateInfo` from a parsed `Certificate`.
fn build_certificate_info(cert: &Certificate) -> Result<CertificateInfo, CriptorError> {
    let der_bytes = cert
        .to_der()
        .map_err(|e| CriptorError::CryptoError(format!("Failed to encode certificate to DER: {}", e)))?;

    let x509_base64 = general_purpose::STANDARD.encode(&der_bytes);
    let issuer_dn = cert.tbs_certificate.issuer.to_string();
    let serial_number = serial_bytes_to_decimal(cert.tbs_certificate.serial_number.as_bytes());

    // Parse validity dates using x509-cert's built-in validity structure
    let validity = &cert.tbs_certificate.validity;
    let not_before = validity_time_to_unix(&validity.not_before)?;
    let not_after = validity_time_to_unix(&validity.not_after)?;

    Ok(CertificateInfo {
        x509_base64,
        issuer_dn,
        serial_number,
        not_before,
        not_after,
    })
}

/// Converts an `x509_cert::time::Time` to a Unix timestamp (i64)
/// by going through `SystemTime`, which both `UtcTime` and `GeneralizedTime`
/// support via their `From` impls in the `der` crate.
fn validity_time_to_unix(time: &x509_cert::time::Time) -> Result<i64, CriptorError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::time::Time;

    let system_time: SystemTime = match time {
        Time::UtcTime(t) => SystemTime::from(*t),
        Time::GeneralTime(t) => SystemTime::from(*t),
    };
    let ts = system_time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(ts)
}

/// Converts a big-endian byte slice representing an integer into its decimal string.
fn serial_bytes_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut().rev() {
            let val = (*d as u32) * 256 + carry;
            *d = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            digits.insert(0, (carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().map(|d| (b'0' + d) as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkcs12::Pkcs12;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Name, X509};

    /// Builds a throwaway self-signed cert + RSA key and returns a PKCS#12 DER blob.
    fn build_test_pkcs12(password: &str) -> Vec<u8> {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", "Test SUNAT").unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        Pkcs12::builder()
            .name("Test")
            .pkey(&pkey)
            .cert(&cert)
            .build2(password)
            .unwrap()
            .to_der()
            .unwrap()
    }

    #[test]
    fn test_parse_pkcs12_and_sign_roundtrip() {
        let der = build_test_pkcs12("password123");

        let (info, private_key) = parse_pkcs12(&der, "password123").unwrap();
        assert!(info.is_valid_now());
        assert!(!info.x509_base64.is_empty());
        assert!(!info.serial_number.is_empty());
        assert!(!info.issuer_dn.is_empty());

        // Sign a 32-byte SHA-256 digest and verify with the matching public key.
        let hash = [7u8; 32];
        let sig_b64 = sign_hash_with_key(&private_key, &hash).unwrap();

        use base64::{engine::general_purpose, Engine as _};
        let signature = general_purpose::STANDARD.decode(sig_b64).unwrap();

        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::sha2::Sha256;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let priv_key = RsaPrivateKey::from_pkcs8_pem(private_key.as_str()).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        pub_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &signature)
            .unwrap();
    }

    #[test]
    fn test_parse_pkcs12_wrong_password_fails() {
        let der = build_test_pkcs12("password123");
        assert!(parse_pkcs12(&der, "wrong-password").is_err());
    }

    #[test]
    fn test_parse_pkcs12_garbage_fails() {
        assert!(parse_pkcs12(&[0u8, 1, 2, 3], "x").is_err());
    }

    #[test]
    fn test_sign_hash_with_invalid_key_fails() {
        let bad_key = SecretString::new("not a pem key".to_string());
        assert!(matches!(
            sign_hash_with_key(&bad_key, &[0u8; 32]),
            Err(CriptorError::InvalidKeyFormat)
        ));
    }
}
