//! A simple script to generate and verify the proof of a given program.

// use sp1_core::io::SP1Stdin;
// use sp1_prover::SP1Prover;
use sp1_sdk::{utils, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    let mut stdin = SP1Stdin::new();
    // utils::setup_logger();

    let encoded_assertion = "omlzaWduYXR1cmVYRzBFAiEAyC5S3pcvtSpmTfNSd8aJRJCQ6PbN7Dnv_oPkZNMLeIwCIBmxCHXKYyGswzp_LwOxoL18puHooxudXWqDgtTvRomdcWF1dGhlbnRpY2F0b3JEYXRhWCV87ytV2nJBCLqRJ5b2df8AvnHVLa4mj6aI00ym0n9wdEAAAAAD";
    let client_data_encoded = "eyJjaGFsbGVuZ2UiOiJhc3NlcnRpb24tdGVzdCJ9";

    let stored_challenge = "assertion-test";
    let client_id = "35MFYY2JY5.co.chiff.attestation-test";
    let prev_counter = 0;
    let public_key_uncompressed_hex = "0437c404fa2bbf8fbcf4ee7080573d5fa80c4f6cc3a22f7db43af92c394e7cd1c880c95ab422972625e8e673af1bda2b096654e9b602895601f925bb5941c53082";
    
    stdin.write(&encoded_assertion);
    stdin.write(&client_data_encoded);
    stdin.write(&stored_challenge);
    stdin.write(&client_id);

    stdin.write(&prev_counter);
    stdin.write(&public_key_uncompressed_hex);
    
    // Prover.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).expect("proving failed");

    // Read output.
    let is_valid_assertion = proof.public_values.read::<bool>();
    println!("proof {:}", is_valid_assertion);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Verify proof.
    // SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
