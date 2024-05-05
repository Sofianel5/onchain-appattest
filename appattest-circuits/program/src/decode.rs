use base64_url::decode;
use cbor::{Decoder};
use serde_cbor::from_slice;

pub fn decodeAttestation(encoded: &str) -> Result<AttestationObject, serde_cbor::Error> {
    let bytes = base64decode(encoded);
    serde_cbor::from_slice(&bytes)
}

fn b46decode(encoded: &str) -> Vec<u8> {
    let decoded = decode(encoded).unwrap();
    let mut d = Decoder::from_bytes(decoded);
    let cbor = d.items().next().unwrap().unwrap();
    return cbor;
}
