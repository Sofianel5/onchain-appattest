use sha2::Digest;
use sha2::Sha256;
use ring::signature;
use ring::signature::UnparsedPublicKey;
use lib::AssertionObject;

pub fn validate_assertion(assertion: AssertionObject, challenge: String, public_key_bytes: Vec<u8>) -> bool {

    // 1. sha256 hash the clientData
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let client_data_hash = hasher.finalize();
    // println!("\nCLIENT DATA HASH: {:?}", client_data_hash);

    // 2. Create nonce.
    let mut hasher = Sha256::new();
    let mut raw_nonce: Vec<u8> = assertion.authenticator_data.as_bytes().to_vec();
    raw_nonce.extend(&client_data_hash);
    
    hasher.update(raw_nonce);
    let nonce = hasher.finalize();

    // 3. Verify signature over nonce.
    let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_bytes);
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