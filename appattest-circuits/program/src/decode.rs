use base64_url;
use serde_cbor;
use lib::AttestationObject;

pub fn decode_attestation(encoded: &str) -> Result<AttestationObject, serde_cbor::Error> {
    let bytes = base64_url::decode(encoded).unwrap().as_slice();
    serde_cbor::from_slice(bytes);
}
