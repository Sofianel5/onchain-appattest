#[macro_use] extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

// TODO: need to download the proving / verifying keys
#[post("/setup")]
fn setup() -> Result<&'static str, Box<dyn Error>> {
    download_keys(
        Some("./keys/proving_key.pk"),
        Some("./keys/verifying_key.vk"),
    )?;
    Ok("Done")
}

/*
 * - need to have internal counter, stored challenge (user-suppplied?)
 */
#[derive(serde::Deserialize)]
struct ProofRequestBody {
    encoded_assertion: String,
    client_data_encoded: String,
    public_key_uncompressed_hex: String,
}

// Generates the proof.
#[post("/prove", format = "application/json", data = "<request_body>")]
fn prove(request_body: Json<ProofRequestBody>) -> Result<String, FromHexError> {
    let proof = generate_proof(
        &request_body.encoded_assertion,
        &request_body.client_data_encoded,
        &request_body.public_key_uncompressed_hex,
    ).unwrap();
    let proof_hex = hex::encode(proof);
    Ok(proof_hex);
}

#[derive(serde::Deserialize)]
struct VerifyRequestBody {
    proof: String,
    verification_key: String, // key path?
}

// Verify the proof.
#[post("/verify", format = "application/json", data = "<request_body>")]
fn verify(request_body: Json<VerifyRequestBody>) -> Result<String, FromHexError> {
    let proof = hex::decode(&request_body.proof)?;
    let verified = verify_proof(proof, &request_body.verification_key).unwrap();
    if verified {
        Ok("Verified")
    } else {
        Ok("Not verified")
    }
}


fn make_cors() -> Cors {
    CorsOptions {
        // 5.
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .expect("error while building CORS")
}

// Main.
#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![
        index,
        setup, 
        prove])
}