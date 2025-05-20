use serde::Deserialize;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

pub fn deserialize_hex_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    
    let value = serde_json::Value::deserialize(deserializer)?;
    
    match value {
        serde_json::Value::String(s) => {
            if s.chars().all(|c| c.is_ascii_hexdigit() || c.is_ascii_uppercase()) {
                Ok(s)
            } else {
                if let Ok(bytes) = BASE64.decode(&s) {
                    Ok(hex::encode(&bytes).to_uppercase())
                } else {
                    Err(Error::custom("Invalid hex or base64 string"))
                }
            }
        },
        _ => Err(Error::custom("Expected a string")),
    }
}