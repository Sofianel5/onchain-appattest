//! A simple program to be proven inside the zkVM.
use base64::prelude::*;

#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::{AttestationObject, AssertionObject};
use attestation::validate_attestation;
use assertion::assertion::validate_assertion;

pub fn main() {
    
    let raw_attestation = sp1_zkvm::io::read::<String>();
    let raw_assertion = sp1_zkvm::io::read::<String>();
    let challenge = sp1_zkvm::io::read::<Vec<u8>>(); 
    let bundle_id = sp1_zkvm::io::read::<String>();
    
    // Decode base64 strings into attestation and assertion objects.
    let attestation = decode_attestation(raw_attestation);
    let assertion = decode_assertion(raw_assertion);

    // Verify attestation and assertion.
    let is_valid_attestation = validate_attestation(attestation, challenge);
    // TODO: get the public key from the attestation
    let is_valid_assertion = validate_assertion(assertion, challenge, public_key_bytes);

    sp1_zkvm::io::commit(&is_valid_attestation);
    sp1_zkvm::io::commit(&is_valid_assertion);
}

pub fn decode_attestation(base64input) -> (AttestationObject) {
    
}

pub fn decode_assertion(base64input) -> (AssertionObject) {
    
}




