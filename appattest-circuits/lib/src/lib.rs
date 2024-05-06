use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttestationStatement {
    pub x5c: Vec<String>, // array of intermediate and leaf certificates.
    pub alg: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde( rename_all = "camelCase")]
pub struct AttestationObject {
    pub fmt: String,
    pub att_stmt: AttestationStatement,
    pub auth_data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssertionObject {
    pub signature: Vec<u8>,
    pub authenticator_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssertionStr {
    pub signature: String,
    pub authenticator_data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestedCredentialData {
    pub aaguid: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticatorData {
    pub rp_id: Vec<u8>,
    pub flags: u8, // TODO: might have to change
    pub counter: u32,
    pub att_data: AttestedCredentialData,
    pub ext_data: Vec<u8>,
}