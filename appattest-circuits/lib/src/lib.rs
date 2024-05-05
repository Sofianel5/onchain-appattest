use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationStatement {
    pub x5c: [Vec<u8>;2], // array of intermediate and leaf certificates.
    pub alg: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationObject {
    pub fmt: String,
    pub att_stmt: AttestationStatement,
    pub auth_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AssertionObject {
    pub signature: Vec<u8>,
    pub authenticator_data: Vec<u8>,
}