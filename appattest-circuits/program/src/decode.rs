use base64_url::decode;
use lib::{AssertionObject, AuthenticatorData, ClientData};
use serde_json;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

use serde_cbor::{Value, from_slice};

// Decode base64 string into assertion object.
pub fn decode_assertion(encoded: String) -> Result<AssertionObject, serde_json::Error> {
    let decoded = URL_SAFE.decode(&encoded.as_bytes()).expect("decoding error");
    let cbor: Value = from_slice(&decoded).expect("decoding error");
    let json_str = serde_json::to_string(&cbor).expect("decoding error");
    let assertion: AssertionObject = serde_json::from_str(&json_str).expect("decoding error");
    
   Ok(assertion)
}

// Decode for AuthenticatorData.
pub fn decode_assertion_auth_data(s: Vec<u8>) -> Result<AuthenticatorData, serde_json::Error> {
    let auth_data = AuthenticatorData {
        rp_id: (s[0..32]).to_vec(),
        flags: s[32],
        counter: u32::from_be_bytes(s[33..37].try_into().unwrap()),
        // att_data: &s[37..],
    };
    Ok(auth_data)
}

// Base64 decode.
pub fn decode_base64_to_bytes(encoded: &String) -> Vec<u8> {
    let decoded = decode(&encoded).unwrap();
    decoded
}

// Decode ClientData.
pub fn decode_client_data(encoded: String) -> Result<ClientData, serde_json::Error> {
    let client_data: ClientData = serde_json::from_str(encoded.to_string().as_str())?;
    Ok(client_data)
}