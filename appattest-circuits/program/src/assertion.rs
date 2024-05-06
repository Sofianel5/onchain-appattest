use sha2::Digest;
use sha2::Sha256;
use ring::signature::ECDSA_P256_SHA256_ASN1;
use ring::signature::UnparsedPublicKey;
use lib::{AssertionObject, ClientData};
use hex;

use crate::decode::decode_assertion_auth_data;
use crate::decode::decode_client_data;

pub fn validate_assertion(assertion: AssertionObject, client_data: Vec<u8>, 
    public_key_uncompressed_hex: String, client_app_id: String, stored_challenge: String, prev_counter: u32) -> bool {

    // 1. sha256 hash the clientData
    let mut hasher = Sha256::new();
    hasher.update(client_data.clone());
    let client_data_hash = hasher.finalize();

    // 2. Create nonce.
    hasher = Sha256::new();
    let mut nonce_raw: Vec<u8> = assertion.authenticator_data.clone();
    nonce_raw.extend(&client_data_hash);
    hasher.update(nonce_raw);
    let nonce_hash = hasher.finalize();

    // 3. Verify signature over nonce.
    let public_key_uncompressed = hex::decode(public_key_uncompressed_hex).expect("decoding error");
    let verifying_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_uncompressed);

    let verification = verifying_key.verify(&nonce_hash, &assertion.signature);
    let verified = match verification {
        Ok(_) => {
            println!("Signature verified!");
            true
        },
        Err(_) => {
            println!("Signature verification failed!");
            false
        },
    };   
    if !verified {
        return false;
    }

    let auth_data = decode_assertion_auth_data(assertion.authenticator_data.clone()).expect("decoding error");
    
    // 4. Verify RP ID.
    hasher = Sha256::new();
    hasher.update(client_app_id.clone());
    let client_app_id_hash = hasher.finalize();
    if auth_data.rp_id != client_app_id_hash.to_vec() {
        println!("RP ID is not equal");
        return false;
    }

    // 5. Verify counter.
    if auth_data.counter <= prev_counter {
        println!("counter is less than prev counter");
        return false;
    }

    // 6. Verify challenge. 
    let client_data_decoded = decode_client_data(std::str::from_utf8(&client_data).unwrap()).expect("decoding error");
    if client_data_decoded.challenge != stored_challenge {
        println!("challenge is not equal");
        return false;
    }

    return verified;
}