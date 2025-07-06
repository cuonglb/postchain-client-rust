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
            } else if let Ok(bytes) = BASE64.decode(&s) {
                Ok(hex::encode(&bytes).to_uppercase())
            } else {
                Err(Error::custom("Invalid hex or base64 string"))
            }
        },
        _ => Err(Error::custom("Expected a string")),
    }
}

pub fn deserialize_args_to_vec_string<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Vec<serde_json::Value> = Vec::deserialize(deserializer)?;
    let mut result = Vec::new();

    if !v.is_empty() {
        if let Some(permissions_value) = v.first() {
            if let Ok(permissions) = serde_json::from_value::<Vec<String>>(permissions_value.clone()) {
                result.extend(permissions);
            } else if let Some(s) = permissions_value.as_str() {
                result.push(s.to_string());
            }
        }
    }

    if v.len() >= 2 {
        if let Some(public_key_value) = v.get(1) {
            if let Some(public_key) = public_key_value.as_str() {
                result.push(public_key.to_string());
            }
        }
    }
    
    Ok(result)
}
