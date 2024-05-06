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
#[serde(rename_all = "camelCase")]
pub struct AssertionObject {
    pub signature: String,
    pub authenticator_data: String,
}