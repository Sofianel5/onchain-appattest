use crate::constants::ROOT_CERT;
use crate::decode::decode_assertion_auth_data;
use base64ct::{Base64, Encoding};
use bytes::Bytes;
use der_parser::parse_der;
use lib::AttestationObject;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashSet;
use x509_cert::der::asn1::OctetString;
use x509_cert::Certificate;
use x509_verify::{der::DecodePem, Error, VerifyingKey};

// Parse b64 to pem.
// #[sp1_derive::cycle_tracker]
fn b64_to_pem(b64: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for i in 0..b64.len() / 64 {
        pem.push_str(&b64[i * 64..(i + 1) * 64]);
        pem.push_str("\n");
    }
    pem.push_str(&b64[(b64.len() / 64) * 64..]);
    pem.push_str("\n-----END CERTIFICATE-----");
    return pem;
}

// Validate certificate chain.
// #[sp1_derive::cycle_tracker]
pub fn validate_certificate_path(cert_path: Vec<String>, leaf_cert_only: bool) -> bool {
    if cert_path.len() != cert_path.iter().collect::<HashSet<_>>().len() {
        panic!("Duplicate certificates in certificate path.");
    }

    let num_runs = if leaf_cert_only { 1 } else { cert_path.len() };

    for i in 0..num_runs {
        // Decode subject certificate.
        let subject_b64_data = cert_path[i].as_str();
        let subject_pem = b64_to_pem(&subject_b64_data);

        let subject_cert = Certificate::from_pem(&subject_pem).unwrap();
        // Decode issuer certificate.
        let issuer_b64_data: &str;
        if i + 1 >= cert_path.len() {
            // If this is the last certificate in the path, then the issuer is the root certificate.
            issuer_b64_data = subject_b64_data;
        } else {
            issuer_b64_data = cert_path[i + 1].as_str();
        }

        let issuer_pem = b64_to_pem(&issuer_b64_data);
        let issuer_cert = Certificate::from_pem(&issuer_pem).unwrap();

        let key = VerifyingKey::try_from(&issuer_cert).unwrap();

        // verify the signature
        match key.verify(&subject_cert) {
            Ok(_) => {}
            Err(Error::Verification) => {
                println!("Verification error");
            }
            Err(e) => {
                println!("Verification error {:?}", e);
                return false;
            }
        }
    }
    true
}

// Validate attestation object.
pub fn validate_attestation(
    attestation: AttestationObject,
    challenge: String,
    key_id: Vec<u8>,
    app_id: String,
    production: bool,
    leaf_cert_only: bool,
) -> bool {
    // 1. Verify certificate chain
    let mut cert_path = attestation.att_stmt.x5c.clone();
    cert_path.push(ROOT_CERT.to_string());

    println!("cycle-tracker-start: validate-cert");
    let cert_chain_valid = validate_certificate_path(cert_path, leaf_cert_only);
    if !cert_chain_valid {
        return false;
    }
    println!("cycle-tracker-end: validate-cert");

    // 2. Create clientDataHash
    println!("cycle-tracker-start: step-2");
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let client_data_hash: Vec<u8> = hasher.finalize().to_vec();
    // println!("client_data_hash: {:?}", STANDARD.encode(&client_data_hash));
    let auth_data_decoded = Base64::decode_vec(&attestation.auth_data);
    if auth_data_decoded.is_err() {
        panic!("Failed to decode auth_data from base64");
    }
    let auth_data_decoded = auth_data_decoded.unwrap();
    println!("cycle-tracker-start: step-2");

    // Concatenate auth_data_decoded and client_data_hash.
    let mut composite_data = auth_data_decoded;
    composite_data.extend(&client_data_hash);

    // 3. Generate nonce
    hasher = Sha256::new();
    hasher.update(composite_data);
    let expected_nonce = hasher.finalize();

    // 4. Obtain credential cert extension with OID 1.2.840.113635.100.8.2 and compare with nonce.
    println!("cycle-tracker-start: cert-parse");
    let credential_certificate =
        Certificate::from_pem(b64_to_pem(&attestation.att_stmt.x5c[0]).as_bytes()).unwrap();
    println!("cycle-tracker-end: cert-parse");

    println!("cycle-tracker-start: cert-parse-bytes");
    let mut credential_cert_octets: Option<OctetString> = None;
    for extension in credential_certificate.tbs_certificate.extensions.unwrap() {
        // Check for the extension with OID 1.2.840.113635.100.8.2
        if extension.extn_id.as_bytes()
            == Bytes::from_static(&[42, 134, 72, 134, 247, 99, 100, 8, 2])
        {
            credential_cert_octets = Some(extension.extn_value);
            break;
        }
    }
    if credential_cert_octets.is_none() {
        panic!("Credential public key not found in certificate.");
    } else {
        let credential_cert_octets_unwrapped = credential_cert_octets.unwrap();
        let cred_cert_octets_bytes = credential_cert_octets_unwrapped.into_bytes();
        let (_rem, seq) = parse_der(&cred_cert_octets_bytes).unwrap();
        let content = &seq.content.as_sequence().unwrap()[0].content;

        // expect content to be variant Unknown(Any<'a>), get data from it
        match content {
            der_parser::der::DerObjectContent::Unknown(data) => {
                let (_new_rem, new_seq) = parse_der(data.data).unwrap();
                match new_seq.content {
                    der_parser::der::DerObjectContent::OctetString(data) => {
                        if data != expected_nonce.to_vec() {
                            panic!("Nonce mismatch.");
                        }
                    }
                    _ => panic!("Expected OctetString content in extension."),
                }
            }
            _ => panic!("Expected Unknown content in extension."),
        }
    }
    println!("cycle-tracker-end: cert-parse-bytes");

    // 5. Get sha256 hash of the credential public key
    let credential_public_key = credential_certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let mut hasher = Sha256::new();
    hasher.update(credential_public_key);
    let credential_public_key_hash = hasher.finalize();
    if credential_public_key_hash.to_vec() != key_id {
        panic!("Public key hash mismatch.");
    }

    // 6. Verify RP ID hash against app_id
    hasher = Sha256::new();
    hasher.update(app_id);
    let app_id_hash = hasher.finalize();
    let auth_data = decode_assertion_auth_data(
        Base64::decode_vec(&attestation.auth_data.clone().to_string()).unwrap(),
    )
    .expect("decoding error");
    if auth_data.rp_id != app_id_hash.to_vec() {
        println!("RP ID: {:?}", Base64::encode_string(&auth_data.rp_id));
        println!("App ID hash: {:?}", Base64::encode_string(&app_id_hash));
        panic!("RP ID hash mismatch.");
    }

    // 7. Verify counter
    if auth_data.counter > 0 {
        panic!("Counter must be 0.");
    }

    // 8. Very aaguid is present and is 16 bytes, if production \x61\x70\x70\x61\x74\x74\x65\x73\x74\x00\x00\x00\x00\x00\x00\x00 or appattestdevelop if dev
    match &auth_data.aaguid {
        Some(aaguid) => {
            if aaguid.len() != 16 {
                panic!("AAGUID must be 16 bytes.");
            }
            if production
                && aaguid.as_slice()
                    != &[
                        0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                    ]
            {
                println!("{:?}", aaguid.as_slice());
                panic!("AAGUID mismatch (prod).");
            } else if aaguid.as_slice()
                != &[
                    0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x64, 0x65, 0x76, 0x65,
                    0x6c, 0x6f, 0x70,
                ]
            {
                panic!("AAGUID mismatch (dev).");
            }
        }
        None => panic!("AAGUID not found."),
    }
    true
}
