use std::collections::HashSet;
use sha2::Digest;
use sha2::Sha256;
use crate::constants::ROOT_CERT;
use bcder::string::OctetString;
use bcder::oid::Oid;
use x509_certificate::certificate::CapturedX509Certificate;
use lib::AttestationObject;
use bytes::Bytes;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der_parser::parse_der;
use crate::decode::decode_assertion_auth_data;

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

pub fn validate_certificate_path(cert_path: Vec<String>) {
    if cert_path.len() != cert_path.iter().collect::<HashSet<_>>().len() {
        panic!("Duplicate certificates in certificate path.");
    }

    for i in 0..cert_path.len() {

        // Decode subject certificate.
        let subject_b64_data = cert_path[i].as_str();
        let subject_pem = b64_to_pem(&subject_b64_data);
        let subject_cert = CapturedX509Certificate::from_pem(subject_pem).unwrap();

        // Decode issuer certificate.
        let issuer_b64_data: &str;
        if i + 1 >= cert_path.len() {
            // If this is the last certificate in the path, then the issuer is the root certificate.
            issuer_b64_data = subject_b64_data;
        } else {
            issuer_b64_data = cert_path[i + 1].as_str();
        }
        let issuer_pem = b64_to_pem(&issuer_b64_data);
        let issuer_cert = CapturedX509Certificate::from_pem(issuer_pem).unwrap();

        // Verify that the subject certificate was issued by the issuer certificate.
        if subject_cert.issuer_name() != issuer_cert.subject_name() {
            panic!("Certificate path is invalid");
        }
        // println!("Subject: ");
        // println!("{}", subject_cert.encode_pem());
        // println!("Issuer: ");
        // println!("{}", issuer_cert.encode_pem());
        // Verify the signature of the subject certificate.
        let verify = subject_cert.verify_signed_by_certificate(issuer_cert);
        if verify.is_err() {
            panic!("Certificate path is invalid, signature verification failed (index {})", i);
        }

    }
}

pub fn validate_attestation(attestation: AttestationObject, challenge: String, key_id: Vec<u8>, app_id: String, production: bool) -> bool {

    // 1. Verify certificates

    let mut cert_path = attestation.att_stmt.x5c.clone();
    cert_path.push(ROOT_CERT.to_string());
    validate_certificate_path(cert_path);

    // 2. Create clientDataHash

    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let client_data_hash: Vec<u8> = hasher.finalize().to_vec();
    println!("client_data_hash: {:?}", STANDARD.encode(&client_data_hash));
    let auth_data_decoded = STANDARD.decode(&attestation.auth_data);
    if auth_data_decoded.is_err() {
        panic!("Failed to decode auth_data from base64");
    }
    let auth_data_decoded = auth_data_decoded.unwrap();

    // Concatenate auth_data_decoded and client_data_hash.
    let mut composite_data = auth_data_decoded;
    composite_data.extend(&client_data_hash);
    println!("Composite data: {:?}", STANDARD.encode(&composite_data));

    // 3. Generate nonce
    hasher = Sha256::new();
    hasher.update(composite_data);
    let expected_nonce = hasher.finalize();
    println!("Expected nonce: {:?}", STANDARD.encode(expected_nonce.to_vec()));

    // 4. Obtain credential cert extension with OID 1.2.840.113635.100.8.2 and compare with nonce.

    let credential_certificate = CapturedX509Certificate::from_pem(
        b64_to_pem(&attestation.att_stmt.x5c[0]).as_bytes()
    ).unwrap();

    let mut credential_cert_octets: Option<OctetString> = None;
    for extension in credential_certificate.iter_extensions() {
        // Check for the extension with OID 1.2.840.113635.100.8.2
        if extension.id == Oid(Bytes::from_static(&[42,134,72,134,247,99,100,8,2])) {
            credential_cert_octets = Some(extension.value.clone());
            break;
        }
    }
    if credential_cert_octets.is_none() {
        panic!("Credential public key not found in certificate.");
    } else {
        let credential_cert_octets_unwrapped = credential_cert_octets.unwrap();
        let cred_cert_octets_bytes = credential_cert_octets_unwrapped.to_bytes();
        let (_rem, seq) = parse_der(&cred_cert_octets_bytes).unwrap();
        let content = &seq.content.as_sequence().unwrap()[0].content;
        // expect content to be variant Unknown(Any<'a>), get data from it
        match content {
            der_parser::der::DerObjectContent::Unknown(data) => {
                println!("Data: {:?}", STANDARD.encode(data.data));
                let (_new_rem, new_seq) = parse_der(data.data).unwrap(); 
                println!("New seq: {:?}", new_seq.content);
                match new_seq.content {
                    der_parser::der::DerObjectContent::OctetString(data) => {
                        println!("Parsed data: {:?}", STANDARD.encode(data));
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

    // 5. Get sha256 hash of the credential public key

    let credential_public_key = credential_certificate.public_key_data();
    let mut hasher = Sha256::new();
    println!("Credential public key: {:?}", STANDARD.encode(&credential_public_key));
    hasher.update(credential_public_key);
    let credential_public_key_hash = hasher.finalize();
    if credential_public_key_hash.to_vec() != key_id {
        panic!("Public key hash mismatch.");
    }

    // 6. Verify RP ID hash against app_id
    hasher = Sha256::new();
    hasher.update(app_id);
    let app_id_hash = hasher.finalize();
    let auth_data = decode_assertion_auth_data(STANDARD.decode(attestation.auth_data.clone()).unwrap()).expect("decoding error");
    if auth_data.rp_id != app_id_hash.to_vec() {
        println!("RP ID: {:?}", STANDARD.encode(&auth_data.rp_id));
        println!("App ID hash: {:?}", STANDARD.encode(&app_id_hash));
        panic!("RP ID hash mismatch.");
    }

    // 7. Verify counter
    if auth_data.counter > 0 {
        panic!("Counter must be 0.");
    }

    // 8. Very aaguid is present and is 16 bytes, if production \x61\x70\x70\x61\x74\x74\x65\x73\x74\x00\x00\x00\x00\x00\x00\x00 or appattestdevelop if dev
    // println!("AAGUID: {:?}", auth_data.aaguid.unwrap());
    match &auth_data.aaguid {
        Some(aaguid) => {
            if aaguid.len() != 16 {
                panic!("AAGUID must be 16 bytes.");
            }
            if production && aaguid.as_slice() != &[0x61,0x70,0x70,0x61,0x74,0x74,0x65,0x73,0x74,0x00,0x00,0x00,0x00,0x00,0x00,0x00] {
                println!("{:?}", aaguid.as_slice());
                panic!("AAGUID mismatch (prod).");
            } else if aaguid.as_slice() != &[0x61,0x70,0x70,0x61,0x74,0x74,0x65,0x73,0x74,0x64,0x65,0x76,0x65,0x6c,0x6f,0x70] {
                panic!("AAGUID mismatch (dev).");
            }
        }
        None => panic!("AAGUID not found."),
    }

    true
}

