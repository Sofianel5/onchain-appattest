use base64_url::decode;
use cbor::{Decoder};
use rustc_serialize::json::{ToJson};
use lib::{AttestationObject, AssertionObject};
use serde_json;

// Decode base64 string into attestation object.
pub fn decode_attestation(encoded: &str) -> Result<AttestationObject, serde_json::Error> {
    let _bytes = base64_url::decode(encoded).unwrap();
    let decoded = decode(encoded).unwrap();
    let mut d = Decoder::from_bytes(decoded);
    let cbor = d.items().next().unwrap().unwrap();
    let json_str = cbor.to_json();
    let attestation: AttestationObject = serde_json::from_str(json_str.to_string().as_str())?;
    Ok(attestation)
}

// Decode base64 string into assertion object.
pub fn decode_assertion(encoded: &str) -> Result<AssertionObject, serde_json::Error> {
    let _bytes = base64_url::decode(encoded).unwrap();
    let decoded = decode(encoded).unwrap();
    let mut d = Decoder::from_bytes(decoded);
    let cbor = d.items().next().unwrap().unwrap();
    let json_str = cbor.to_json();
    let assertion: AssertionObject = serde_json::from_str(json_str.to_string().as_str())?;
    Ok(assertion)
}