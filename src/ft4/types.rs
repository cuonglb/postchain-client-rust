use serde::{Deserialize, Serialize};
use crate::ft4::utils::deserialize_hex_string;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDescriptor {
    #[serde(rename = "account_id")]
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub account_id: String,
    pub args: Vec<serde_json::Value>,
    #[serde(rename = "auth_type")]
    pub auth_type: String,
    pub created: i64,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub id: String,
    pub rules: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDescriptorArgs {
    #[serde(rename = "0")]
    pub permissions: Vec<String>,
    #[serde(rename = "1")]
    pub public_key: String,
}
