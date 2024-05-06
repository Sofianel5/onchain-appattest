use base64_url::decode;
use cbor::{Decoder};
use rustc_serialize::json::{ToJson};
use lib::{AttestationObject, AssertionObject, AssertionStr, AuthenticatorData, ClientData};
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
    
    // Base64 Decode.
    let signature_bytes = STANDARD.decode(&assertion_str.signature).expect("signature decoding error");
    let auth_data_bytes = STANDARD.decode(&assertion_str.authenticator_data).expect("auth data decoding error");
    
    // Return AssertionObject.
    let assertion = AssertionObject {
        signature: signature_bytes,
        authenticator_data: auth_data_bytes,
    };
    Ok(assertion)
}

// Decode for AuthenticatorData.
pub fn decode_assertion_auth_data(s: Vec<u8>) -> Result<AuthenticatorData, serde_json::Error> {
    let auth_data = AuthenticatorData {
        rp_id: (&s[0..32]).to_vec(),
        flags: s[32],
        counter: u32::from_be_bytes(s[33..37].try_into().unwrap()),
        // att_data: &s[37..],
    };
    Ok(auth_data)
}

// Base64 decode.
pub fn base64_to_bytes(encoded: &str) -> Vec<u8> {
    let decoded = decode(encoded).unwrap();
    decoded
}

// Decode ClientData.
pub fn decode_client_data(encoded: &str) -> Result<ClientData, serde_json::Error> {
    let clientData: ClientData = serde_json::from_str(encoded)?;
    Ok(clientData)
}