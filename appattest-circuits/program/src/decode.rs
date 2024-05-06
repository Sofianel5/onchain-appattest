use base64_url::decode;
use cbor::{Decoder};
use rustc_serialize::json::{ToJson};
use lib::{AttestationObject, AssertionObject, AssertionStr, AuthenticatorData};
use serde_json;
use base64::{engine::general_purpose::STANDARD, Engine as _};

// Decode base64 string into attestation object.
pub fn decode_attestation(encoded: &str) -> Result<AttestationObject, serde_json::Error> {
    let decoded = decode(encoded).unwrap();
    let mut d = Decoder::from_bytes(decoded);
    let cbor = d.items().next().unwrap().unwrap();
    let json_str = cbor.to_json();
    let attestation: AttestationObject = serde_json::from_str(json_str.to_string().as_str())?;
    Ok(attestation)
}

// Decode base64 string into assertion object.
pub fn decode_assertion(encoded: &str) -> Result<AssertionObject, serde_json::Error> {
    // CBOR decode.
    let decoded = decode(encoded).unwrap();
    let mut d = Decoder::from_bytes(decoded);
    let cbor = d.items().next().unwrap().unwrap();
    let json_str = cbor.to_json();
    let assertion_str: AssertionStr = serde_json::from_str(json_str.to_string().as_str())?;

    println!("\nBASE64 SIGNATURE: {:?}", assertion_str.signature);
    println!("BASE64 AUTH DATA: {:?}\n", assertion_str.authenticator_data);
    
    
    // Base64 Decode.
    let signature_bytes = STANDARD.decode(&assertion_str.signature).expect("signature decoding error");

    // Return AssertionObject.
    let assertion = AssertionObject {
        signature: signature_bytes,
        authenticator_data: auth_data,
    };
    Ok(assertion)
}

// Decode for AuthenticatorData.
pub fn decode_auth_data(encoded: &str) -> Result<AuthenticatorData, serde_json::Error> {
    let decoded = decode(encoded).unwrap();
    let mut d = Decoder::from_bytes(decoded);
    let cbor = d.items().next().unwrap().unwrap();
    let json_str = cbor.to_json();
    let auth_data: AuthenticatorData = serde_json::from_str(json_str.to_string().as_str())?;

    Ok(auth_data)
}
