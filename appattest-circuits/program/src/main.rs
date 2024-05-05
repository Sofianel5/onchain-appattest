//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use lib::{AttestationObject, AssertionObject};

pub fn main() {
    let attestation = sp1_zkvm::io::read::<AttestationObject>();
    let assertion = sp1_zkvm::io::read::<AssertionObject>();

    let valid_attestation = validate_attestation(attestation);
    let valid_assertion = validate_assertion(assertion);

    sp1_zkvm::io::commit(&valid_attestation);
    sp1_zkvm::io::commit(&valid_assertion);
}

pub fn validate_attestation(attestation: AttestationObject) -> bool {
    // TODO: validate the attestation
    true
}

pub fn validate_assertion(assertion: AssertionObject) -> bool {
    // TODO: validate the assertion
    true
}
