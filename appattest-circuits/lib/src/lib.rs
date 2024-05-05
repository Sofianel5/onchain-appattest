use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttestationStatement {
    pub x5c: Vec<String>, // array of intermediate and leaf certificates.
    pub alg: i32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde( rename_all = "camelCase")]
pub struct AttestationObject {
    pub fmt: String,
    pub att_stmt: AttestationStatement,
    pub auth_data: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssertionObject {
    pub signature: Vec<u8>,
    pub authenticator_data: Vec<u8>,
}