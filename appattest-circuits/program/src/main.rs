//! A simple program to be proven inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

mod decode;
mod constants;
use decode::decode_attestation;
use decode::decode_assertion;
use base64::prelude::*;

mod attestation;
use attestation::validate_attestation;
use decode::base64_to_bytes;

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

    // decode assertion object (assertion is CBOR base64 encoded, client data is base64 encoded)
    let assertion = decode_assertion(encoded_assertion).unwrap();
    let client_data_decoded = base64_to_bytes(client_data_encoded);

    let is_valid_attestation = validate_assertion(assertion, client_data_decoded, public_key_uncompressed_hex.to_string(), client_id.to_string(), stored_challenge.to_string(), prev_counter);
    println!("{}", is_valid_attestation);
    sp1_zkvm::io::commit(&is_valid_attestation);
}





