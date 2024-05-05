use sha2::Digest;
use sha2::Sha256;
use ring::signature::ECDSA_P256_SHA256_ASN1;
use ring::signature::UnparsedPublicKey;

pub fn validate_assertion(assertion: AssertionObject, challenge: Vec<u8>, public_key_bytes: Vec<u8>) -> bool {

    // 1. sha256 hash the clientData
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let client_data_hash = hasher.finalize();

    // 2. Create nonce.
    let mut hasher = Sha256::new();
    let mut raw_nonce = assertion.authenticator_data;
    raw_nonce.extend(&client_data_hash);
    
    hasher.update(raw_nonce);
    let nonce = hasher.finalize();

    // 3. Verify signature over nonce.
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_bytes);
    let verification = public_key.verify(&nonce, assertion.signature.as_ref());

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

    // 4. Verify RP ID.

    // 5. Verify counter.

    // 6. Verify challenge. 

    return verified;
}