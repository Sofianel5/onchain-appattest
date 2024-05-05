use base64_url::decode;
use cbor::{Decoder};
use rustc_serialize::json::{ToJson};
use lib::AttestationObject;
use serde_json;

pub fn decode_attestation(encoded: &str) -> Result<AttestationObject, serde_json::Error> {
    let bytes = base64_url::decode(encoded).unwrap();
    let decoded = decode(encoded).unwrap();
    let mut d = Decoder::from_bytes(decoded);
    let cbor = d.items().next().unwrap().unwrap();
    let json_str = cbor.to_json();
    let attestation: AttestationObject = serde_json::from_str(json_str.to_string().as_str())?;
    Ok(attestation)
}