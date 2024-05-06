//! A simple program to be proven inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

mod decode;
mod constants;
use decode::decode_assertion;
use decode::decode_base64_to_bytes;  

mod assertion;
use assertion::validate_assertion;

pub fn main() {
    // assertion object
    let encoded_assertion = sp1_zkvm::io::read::<String>();
    let client_data_encoded = sp1_zkvm::io::read::<String>();

    // verification params
    let stored_challenge = sp1_zkvm::io::read::<String>();
    let client_id = sp1_zkvm::io::read::<String>();
    let prev_counter = sp1_zkvm::io::read::<u32>();
    let public_key_uncompressed_hex = sp1_zkvm::io::read::<String>();

    //------------------ ATTESTATION ------------------ // 
    
    // todo: sofiane

    //------------------ ASSERTION ------------------ //

    // let encoded_assertion = "omlzaWduYXR1cmVYRzBFAiEAyC5S3pcvtSpmTfNSd8aJRJCQ6PbN7Dnv_oPkZNMLeIwCIBmxCHXKYyGswzp_LwOxoL18puHooxudXWqDgtTvRomdcWF1dGhlbnRpY2F0b3JEYXRhWCV87ytV2nJBCLqRJ5b2df8AvnHVLa4mj6aI00ym0n9wdEAAAAAD";
    // let client_data_encoded = "eyJjaGFsbGVuZ2UiOiJhc3NlcnRpb24tdGVzdCJ9";

    // let stored_challenge = "assertion-test";
    // let client_id = "35MFYY2JY5.co.chiff.attestation-test";
    // let prev_counter = 0;
    // let public_key_uncompressed_hex = "0437c404fa2bbf8fbcf4ee7080573d5fa80c4f6cc3a22f7db43af92c394e7cd1c880c95ab422972625e8e673af1bda2b096654e9b602895601f925bb5941c53082";

    // decode assertion object (assertion is CBOR base64 encoded, client data is base64 encoded)
    let assertion = decode_assertion(encoded_assertion.to_string()).unwrap();
    let client_data_decoded = decode_base64_to_bytes(&client_data_encoded.to_string());

    let is_valid_attestation = validate_assertion(assertion, client_data_decoded, public_key_uncompressed_hex.to_string(), client_id.to_string(), stored_challenge.to_string(), prev_counter);
    // println!("{}", is_valid_attestation);
    sp1_zkvm::io::commit(&is_valid_attestation);
}





