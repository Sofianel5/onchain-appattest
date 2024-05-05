//! A simple script to generate and verify the proof of a given program.

use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-sp1-zkvm-elf");

fn main() {
    // Generate proof.
    let mut stdin = SP1Stdin::new();
    // stdin.write(&5000u32);
    
    // TODO: replace with real attestation and assertion

    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Read output.
    let valid_attestation = proof.stdout.read::<bool>();
    let valid_assertion = proof.stdout.read::<bool>();

    println!("attestation is valid: {}", valid_attestation);
    println!("assertion is valid: {}", valid_assertion);

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
