use std::collections::HashSet;
use sha2::Digest;
use sha2::Sha256;
use crate::constants::ROOT_CERT;
use bcder::string::OctetString;
use bcder::oid::Oid;
use x509_certificate::certificate::CapturedX509Certificate;
use lib::AttestationObject;
use bytes::Bytes;

fn b64_to_pem(b64: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for i in 0..b64.len() / 64 {
        pem.push_str(&b64[i * 64..(i + 1) * 64]);
        if i + 1 < b64.len() / 64 {
            pem.push_str("\n");
        }
    }
    pem.push_str("\n-----END CERTIFICATE-----");
    return pem;
}

pub fn validate_certificate_path(cert_path: Vec<String>) {
    if cert_path.len() != cert_path.iter().collect::<HashSet<_>>().len() {
        panic!("Duplicate certificates in certificate path.");
    }

    for i in 0..cert_path.len() {

        // Decode subject certificate.
        let subject_b64_data = cert_path[i].as_str();
        let subject_pem = b64_to_pem(&subject_b64_data);
        let subject_cert = CapturedX509Certificate::from_pem(subject_pem.as_bytes()).unwrap();

        // Decode issuer certificate.
        let issuer_b64_data: &str;
        if i + 1 >= cert_path.len() {
            // If this is the last certificate in the path, then the issuer is the root certificate.
            issuer_b64_data = subject_b64_data;
        } else {
            issuer_b64_data = cert_path[i + 1].as_str();
        }
        let issuer_pem = b64_to_pem(&issuer_b64_data);
        let issuer_cert = CapturedX509Certificate::from_pem(issuer_pem.as_bytes()).unwrap();

        // Verify that the subject certificate was issued by the issuer certificate.
        if subject_cert.issuer_name() != issuer_cert.subject_name() {
            panic!("Certificate path is invalid");
        }

        // Verify the signature of the subject certificate.
        let verify = subject_cert.verify_signed_by_certificate(&issuer_cert);
        if verify.is_err() {
            panic!("Certificate path is invalid, signature verification failed.");
        }

    }
}

pub fn validate_attestation(attestation: AttestationObject, challenge: String, key_id: Vec<u8>, _app_id: String, _production: bool) -> bool {

    // 1. Verify certificates

    let mut cert_path = attestation.att_stmt.x5c.clone();
    cert_path.push(ROOT_CERT.to_string());
    validate_certificate_path(cert_path);

    // 2. Create clientDataHash

    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let client_data_hash: String = String::from_utf8(hasher.finalize().to_vec()).unwrap();
    let composite_hash = attestation.auth_data + &client_data_hash;

    // 3. Generate nonce
    hasher = Sha256::new();
    hasher.update(composite_hash);
    let expected_nonce = hasher.finalize();

    // 4. Obtain credential cert extension with OID 1.2.840.113635.100.8.2 and compare with nonce.

    let credential_certificate = CapturedX509Certificate::from_pem(
        b64_to_pem(&attestation.att_stmt.x5c[0]).as_bytes()
    ).unwrap();

    let mut credential_cert_octets: Option<OctetString> = None;
    for extension in credential_certificate.iter_extensions() {
        // Check for the extension with OID 1.2.840.113635.100.8.2
        if extension.id == Oid(Bytes::from_static(&[42,134,72,134,247,99,100,8,2])) {
            credential_cert_octets = Some(extension.value.clone());
        }
    }
    if credential_cert_octets.is_none() {
        panic!("Credential public key not found in certificate.");
    } else if credential_cert_octets.unwrap() != OctetString::new(Bytes::from_iter(expected_nonce.to_vec())) {
        panic!("Nonce mismatch.");
    }

    // 5. Get sha256 hash of the credential public key

    let credential_public_key = credential_certificate.public_key_data();
    let mut hasher = Sha256::new();
    hasher.update(credential_public_key);
    let credential_public_key_hash = hasher.finalize();
    if credential_public_key_hash.to_vec() != key_id {
        panic!("Public key hash mismatch.");
    }
    return true;
    // 6. Verify RP ID hash

}

