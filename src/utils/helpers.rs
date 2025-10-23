#![allow(warnings)]

use std::{str::FromStr, convert::TryInto};
use sfv::{Dictionary, Parser, ListEntry, BareItem};
use reqwest::header::HeaderMap;
use crate::utils::operation::Params;
use std::collections::BTreeMap;

pub const QUERY_REQUEST_SIGNATURE_HEADER: &str = "X-Accept-Query-Response-Signature";
pub const QUERY_RESPONSE_SIGNATURE_HEADER: &str = "X-Query-Response-Signature";
pub const QUERY_RESPONSE_BLOCK_HEIGHT_HEADER: &str = "X-Block-Height";

#[derive(Debug)]
pub struct QueryResponseSignaturedHeader {
    pub alg: String,
    pub subject: [u8; 33], // a compressed secp256k1 public key | [u8; 65] for uncompressed
    pub sig: [u8; 64] // a secp256k1 signature in compact format
}

#[derive(Debug)]
pub struct QueryResponseSignatureData {
    pub name: String,
    pub args: Params,
    pub height: i64,
    pub response: Params
}

fn err_missing_or_invalid_key(key: &str) -> String {
    format!("Missing or invalid list entry for '{}' field", key)
}

fn err_invalid_data_type(key: &str, expected_type: &str) -> String {
    format!("'{}' field found, but is not a {}", key, expected_type)
}

fn get_string(dict: &Dictionary, key: &str) -> Result<String, String> {
    match dict.get(key) {
        Some(ListEntry::Item(item)) => {
            if let BareItem::String(val) = &item.bare_item {
                Ok(val.to_string())
            } else {
                Err(err_invalid_data_type(key, "String"))
            }
        },
        _ => Err(err_missing_or_invalid_key(key)),
    }
}

fn get_byte_sequence<const N: usize>(dict: &Dictionary, key: &str) -> Result<[u8; N], String> {
    match dict.get(key) {
        Some(ListEntry::Item(item)) => {
            if let BareItem::ByteSequence(val) = &item.bare_item {
                val.as_slice().try_into()
                    .map_err(|_| format!("'{}' field has incorrect length (expected {} bytes, got {})", key, N, val.len()))
            } else {
                Err(err_invalid_data_type(key, "ByteSequence"))
            }
        },
        _ => Err(err_missing_or_invalid_key(key)),
    }
}

impl FromStr for QueryResponseSignaturedHeader {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        let sfv_dict: Dictionary = Parser::new(s)
            .parse()
            .map_err(|err| format!("Failed to parse structured header string: {}", err))?;

        let alg: String = get_string(&sfv_dict, "alg")?;
        let subject: [u8; 33] = get_byte_sequence::<33>(&sfv_dict, "subject")?;
        let sig: [u8; 64] = get_byte_sequence::<64>(&sfv_dict, "sig")?;

        Ok(QueryResponseSignaturedHeader { alg, subject, sig })
    }
}

impl QueryResponseSignatureData {
    pub fn to_params_dict(self) -> Params {
        let dict: BTreeMap<String, Params> = BTreeMap::from([
                    ("name".to_string(), Params::Text(self.name)),
                    ("args".to_string(), self.args),
                    ("height".to_string(), Params::Integer(self.height)),
                    ("response".to_string(), self.response),
                ]);
        Params::Dict(dict)
    }
}

pub fn get_query_response_block_height(headers: &HeaderMap) -> Option<u64> {
    headers.get(QUERY_RESPONSE_BLOCK_HEIGHT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

pub fn get_query_response_signature_header(headers: &HeaderMap) -> Option<QueryResponseSignaturedHeader> {
    headers.get(QUERY_RESPONSE_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|s| QueryResponseSignaturedHeader::from_str(s).ok())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use crate::utils::hasher::{gtv_hash, verify_signature};

    /// Document: https://gitlab.com/chromaway/core/postchain/-/blob/3.43.0/postchain-base/src/main/resources/restapi-docs/postchain-restapi.yaml?ref_type=tags#L1072-1104
    use super::*;
    use hex;

    #[test]
    fn test_parse_query_structured_header_success() {
        let header_str = r#"alg="secp256k1", subject=:A6MBaXvfzXBDE7pI5R1WdUPyoYIDHv1pFd3Ae7zE4WBw:, sig=:QCZVnPLGwzkKw+BZHb22vxNcroxfb6FPeWkW7z/xr01hul2EdUSsCRUm6M+LpsxTc781OK3i9Vgb72wbmJXI7A==:"#;

        let parsed_header = QueryResponseSignaturedHeader::from_str(header_str).expect("Failed to parse valid header string");

        assert_eq!(parsed_header.alg, "secp256k1");
        assert_eq!(hex::encode(parsed_header.subject), "03a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070");
        assert_eq!(hex::encode(parsed_header.sig), "4026559cf2c6c3390ac3e0591dbdb6bf135cae8c5f6fa14f796916ef3ff1af4d61ba5d847544ac091526e8cf8ba6cc5373bf3538ade2f5581bef6c1b9895c8ec");
    }

    #[test]
    fn test_parse_query_structured_header_missing_field() {
        let header_str = r#"alg="secp256k1", sig=:QCZVnPLGwzkKw+BZHb22vxNcroxfb6FPeWkW7z/xr01hul2EdUSsCRUm6M+LpsxTc781OK3i9Vgb72wbmJXI7A==:"#;

        let error = QueryResponseSignaturedHeader::from_str(header_str).unwrap_err();
        assert!(error.contains("Missing or invalid list entry for 'subject' field"));
    }

    #[test]
    fn test_parse_query_structured_header_invalid_type() {
        let header_str = r#"alg="secp256k1", subject="not_a_byte_sequence", sig=:QCZVnPLGwzkKw+BZHb22vxNcroxfb6FPeWkW7z/xr01hul2EdUSsCRUm6M+LpsxTc781OK3i9Vgb72wbmJXI7A==:"#;

        let error = QueryResponseSignaturedHeader::from_str(header_str).unwrap_err();
        assert!(error.contains("'subject' field found, but is not a ByteSequence"));
    }

    #[test]
    fn test_parse_query_structured_header_incorrect_length() {
        let header_str = r#"alg="secp256k1", subject=:A6MBaXvfzXBDE7pI5R1WdUPyoYIDHv1pFd3Ae7zE4WB:, sig=:QCZVnPLGwzkKw+BZHb22vxNcroxfb6FPeWkW7z/xr01hul2EdUSsCRUm6M+LpsxTc781OK3i9Vgb72wbmJXI7A==:"#;

        let error = QueryResponseSignaturedHeader::from_str(header_str).unwrap_err();
        assert!(error.contains("'subject' field has incorrect length (expected 33 bytes, got 32)"));
    }

    #[test]
    fn test_hash_and_sign_query_response_signature_data() {
        let sample_qrsd = QueryResponseSignatureData {
            name: "api_version".to_string(),
            args: Params::Dict(BTreeMap::new()),
            height: 1260081,
            response: Params::Integer(101)
        }.to_params_dict();

        let hash_version = 2;

        let hashed_sample_qrsd = gtv_hash(sample_qrsd, hash_version).unwrap();

        let sample_response_pubkey = "0350fe40766bc0ce8d08b3f5b810e49a8352fdd458606bd5fafe5acdcdc8ff3f57";
        let sample_response_signature = "1343d7602a4319bd9e82ebb48426054cac6bad34731a8fd897c7d58536fff13f278dfe7a44f4cd3ffa393e49a7c2e93d3652266bb379a532159ba81bab61657e";

        assert_eq!(hex::encode(hashed_sample_qrsd), "40f21d1c30ac1a6739b8bf5c050f72124eb647a916447e7ebb0748726f35bf48");

        let result = verify_signature(
            hex::decode(sample_response_pubkey).unwrap().try_into().unwrap(),
            hex::decode(sample_response_signature).unwrap().try_into().unwrap(),
            hashed_sample_qrsd
        ).expect("Signature verification failed");

        assert!(result);
    }
}
