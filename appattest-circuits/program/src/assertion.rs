use sha2::Digest;
use sha2::Sha256;
// use ring::signature;
// use ring::signature::UnparsedPublicKey;
use lib::AssertionObject;
use p256::{ecdsa::{VerifyingKey, signature::Verifier, Signature}, PublicKey};
use hex;

pub fn validate_assertion(assertion: AssertionObject, client_data: String, public_key_uncompressed_hex: String) -> bool {

    // 1. sha256 hash the clientData
    let mut hasher = Sha256::new();
    hasher.update(client_data);
    let client_data_hash = hasher.finalize();

    // 2. Create nonce.
    let mut hasher = Sha256::new();
    let mut raw_nonce: Vec<u8> = assertion.authenticator_data;
    raw_nonce.extend(&client_data_hash);
    
    hasher.update(raw_nonce);
    let nonce = hasher.finalize();

    // 3. Verify signature over nonce.
    let public_key_uncompressed = hex::decode(public_key_uncompressed_hex).expect("decoding error");
    let public_key = PublicKey::from_sec1_bytes(&public_key_uncompressed).expect("import error");
    let verifying_key = VerifyingKey::from(&public_key);

    let signature = Signature::from_der(&assertion.signature).expect("deserializing error");

    println!("\nNONCE: {:?}", nonce);
    println!("\nVERIFYING KEY: {:?}", verifying_key);
    println!("\nSIGNATURE: {:?}", signature);
    println!("");

    let verification = verifying_key.verify(&nonce, &signature);
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