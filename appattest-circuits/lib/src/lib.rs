use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationStatement {
    pub x5c: Vec<String>,
    pub receipt: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationObject {
    pub fmt: String,
    pub attStmt: AttestationStatement,
    pub authData: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AssertionObject {
    pub signature: String,
    pub authenticatorData: String,
}