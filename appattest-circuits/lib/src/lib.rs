use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationStatement {
    pub x5c: [Vec<u8>;2], // array of intermediate and leaf certificates.
    pub receipt: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationObject {
    pub fmt: String,
    pub attStmt: AttestationStatement,
    pub authData: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AssertionObject {
    pub signature: Vec<u8>,
    pub authenticatorData: Vec<u8>,
}