use sha2::Digest;
use sha2::Sha256;
mod constants;
use constants::root_cert;
use x509_certificate::certificate::CapturedX509Certificate;

fn b64_to_pem(b64: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for i in 0..b64.len() / 64 {
        pem.push_str(&b64[i * 64..(i + 1) * 64]);
        pem.push_str("\n");
    }
    pem.push_str("\n-----END CERTIFICATE-----");
    return pem;
}

pub fn validate_certificate_path(cert_path: Vec<String>) {
    if (cert_path.len() != cert_path.iter().collect().len()) {
        panic!("Duplicate certificates in certificate path.");
    }

    for i in 0..cert_path.len() {

        // Decode subject certificate.
        let subject_b64_data = cert_path[i].as_str();
        let subject_pem = b64_to_pem(&subject_b64_data);
        let subject_cert = CapturedX509Certificate::from_pem(subject_pem.as_bytes()).unwrap();

        // Decode issuer certificate.
        let issuer_b64_data: String;
        if i + 1 >= cert_path.len() {
            // If this is the last certificate in the path, then the issuer is the root certificate.
            issuer_b64_data = subject_b64_data;
        } else {
            issuer_b64_data = cert_path[i + 1].as_str();
        }
        let issuer_pem = b64_to_pem(&issuer_b64_data);
        let issuer_cert = CapturedX509Certificate::from_pem(issuer_pem.as_bytes()).unwrap();

        // Verify that the subject certificate was issued by the issuer certificate.
        if (subject_cert.issuer() != issuer_cert.subject()) {
            panic!("Certificate path is invalid, {} != {}", subject_cert.issuer(), issuer_cert.subject());
        }

        // Verify the signature of the subject certificate.
        if (!subject_cert.verify_signed_by_certificate(&issuer_cert)) {
            panic!("Certificate path is invalid, signature verification failed.");
        }

    }
}

pub fn validate_attestation(attestation: AttestationObject, challenge: String) -> bool {

    // 1. Verify certificates

    let cert_path = attestation.att_stmt.x5c.clone();
    cert_path.push_str(root_cert);
    validate_certificate_path(cert_path);

    // 2. Verify attestation statement

    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let client_data_hash = hasher.finalize().to_string();
    let composite_hash = attestation.auth_data + client_data_hash;
    hasher = Sha256::new();
    hasher.update(composite_hash);
    let expected_nonce = hasher.finalize().to_string();

    let credential_certificate = CapturedX509Certificate::from_pem(
        b64_to_pem(&attestation.att_stmt.x5c[0]).as_bytes()
    ).unwrap();
    for extension in credential_certificate.iter_extensions() {
        // Check for the extension with OID 1.2.840.113635.100.8.2
        if (extension.oid() == Oid(Bytes::from_static(&[42,134,72,134,247,99,100,8,2]))) {
            
        }
    }
    
}