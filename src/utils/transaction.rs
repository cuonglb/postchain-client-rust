//! Transaction handling and digital signature functionality.
//! 
//! This module provides functionality for creating, managing, and signing blockchain
//! transactions. It supports single and multi-signature transactions using ECDSA
//! with the secp256k1 curve.
//! 
//! # Features
//! - Transaction creation and management
//! - Transaction ID generation
//! - Single and multi-signature support
//! - GTV (Generic Tree Value) encoding
//! 
//! # Example
//! ```
//! use crate::utils::transaction::{Transaction, TransactionStatus};
//!
//! let brid = "FA189BEBA886669CF7DF7DB3D8CFD878D1F80ED360BDCF26B43ABE3D9B3D53CC"; // Replace with actual blockchain RID
//!
//! let brid_to_vec = hex::decode(brid).unwrap();
//! 
//! // Create a new transaction
//! let mut tx = Transaction::new(
//!     brid_to_vec,    // blockchain RID
//!     Some(vec![]),   // operations
//!     None,           // signers
//!     None            // signatures
//! );
//!
//! // Sign the transaction
//! let private_key1 = "C70D5A77CC10552019179B7390545C46647C9FCA1B6485850F2B913F87270300";  // Replace with actual private key
//! tx.sign(&hex::decode(private_key1).unwrap().try_into().expect("Invalid private key 1")).expect("Failed to sign transaction");
//!
//! // Multi sign the transaction
//! let private_key2 = "17106092B72489B785615BD2ACB2DDE8D0EA05A2029DCA4054987494781F988C";  // Replace with actual private key
//! tx.sign(&[
//! &hex::decode(private_key1).unwrap().try_into().expect("Invalid private key 1"),
//! &hex::decode(private_key2).unwrap().try_into().expect("Invalid private key 2")
//! ]).expect("Failed to multi sign transaction");
//!
//! // Sign the transaction from raw private key
//! tx.sign_from_raw_priv_key(private_key1);
//!
//! // Multi sign the transaction from raw private keys
//! tx.multi_sign_from_raw_priv_keys(&[private_key1, private_key2]);
//!
//! ```


use crate::encoding::gtv;
use crate::utils::hasher::gtv_hash;
use crate::encoding::gtv::decode as gtv_decode;
use super::{hasher, operation::Operation, operation::Params as Op_Params};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Message, ecdsa::Signature};
use hex::FromHex;

/// Represents the current status of a transaction in the blockchain.
#[derive(Debug, PartialEq)]
pub enum TransactionStatus {
    /// Transaction was rejected by the blockchain
    REJECTED,
    /// Transaction has been confirmed and included in a block
    CONFIRMED,
    /// Transaction is waiting to be included in a block
    WAITING,
    /// Transaction status is unknown
    UNKNOWN
}

/// Represents a blockchain transaction with operations and signatures.
/// 
/// A transaction contains a list of operations to be executed, along with
/// the necessary signatures to authorize these operations. It supports
/// both single and multi-signature scenarios.
#[derive(Debug)]
pub struct Transaction {
    /// Unique identifier of the blockchain this transaction belongs to
    pub blockchain_rid: Vec<u8>,
    /// List of operations to be executed in this transaction
    pub operations: Option<Vec<Operation>>,
    /// List of public keys of the signers
    pub signers: Option<Vec<Vec<u8>>>,
    /// List of signatures corresponding to the signers
    pub signatures: Option<Vec<Vec<u8>>>,
    // Hash version (default is 1)
    pub merkle_hash_version: u8
}

/// Helper macro to extract a field from a dictionary with type checking.
///
/// This macro simplifies extracting a value from a dictionary (typically a HashMap)
/// where the value is expected to be of a specific enum variant. It performs a type check
/// and returns a reference to the inner value if the type matches, or returns an error if not.
///
/// # Parameters
/// - `$dict`: The dictionary (e.g., &HashMap<String, Params>) to extract from.
/// - `$key`: The key to look up in the dictionary.
/// - `$variant`: The enum variant to match (e.g., `Op_Params::ByteArray`).
/// - `$err`: The error string to use if the field is missing or of the wrong type.
///
/// # Returns
/// - On success: a reference to the inner value of the matched variant.
/// - On failure: returns from the enclosing function with an error message.
///
/// # Example
/// ```
/// let value = extract_field!(my_dict, "blockHeader", crate::utils::operation::Params::ByteArray, "blockHeader");
/// ```
macro_rules! extract_field {
    ($dict:expr, $key:expr, $variant:path, $err:expr) => {
        match $dict.get($key) {
            Some($variant(val)) => val,
            _ => return Err(format!("Missing or invalid field: {}", $key)),
        }
    };
}

impl Default for Transaction {
    /// Creates a new Transaction with default values and performs automatic initialization.
    /// 
    /// # Example
    /// ```
    /// let mut tx = Transaction {
    ///     blockchain_rid: hex::decode(brid).unwrap(),
    ///     operations: Some(ops),
    ///     ..Default::default()  // This will trigger auto initialization
    /// };
    /// ```
    fn default() -> Self {
        Self {
            blockchain_rid: vec![],
            operations: None,   
            signers: None,      
            signatures: None,
            merkle_hash_version: 1
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TransactionConfirmationProofData {
  pub block_header: Vec<u8>,
  pub hash: Vec<u8>,
  pub tx_index: i64,
  pub witness: Vec<u8>,
  pub merkle_proof_tree: Vec<crate::utils::operation::Params>
}

#[derive(Debug, serde::Deserialize)]
pub struct TransactionInfo {
    #[serde(rename = "blockRID")]
    pub block_rid: String,
    #[serde(rename = "blockHeight")]
    pub block_height: i64,
    #[serde(rename = "blockHeader")]
    pub block_header: String,
    pub witness: String,
    pub witnesses: Vec<String>,
    #[serde(rename = "witnessSignatures")]
    pub witness_signatures: Vec<String>,
    pub timestamp: i64,
    #[serde(rename = "txRID")]
    pub tx_rid: String,
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    #[serde(rename = "txData")]
    pub tx_data: String
}

impl Transaction {
    /// Creates a new transaction with the specified parameters.
    ///
    /// # Arguments
    /// * `blockchain_rid` - Unique identifier of the blockchain
    /// * `operations` - Optional list of operations to be executed
    /// * `signers` - Optional list of public keys of the signers
    /// * `signatures` - Optional list of signatures
    /// 
    /// # Returns
    /// A new Transaction instance
    pub fn new(blockchain_rid: Vec<u8>,
        operations: Option<Vec<Operation>>,
        signers: Option<Vec<Vec<u8>>>,
        signatures: Option<Vec<Vec<u8>>>) -> Self {
        Self {
            blockchain_rid,
            operations,
            signers,
            signatures,
            ..Default::default()
        }
    }

    /// Returns the hex-encoded GTV (Generic Tree Value) representation of the transaction.
    /// 
    /// This method encodes the transaction into GTV format and returns it as a
    /// hexadecimal string.
    /// 
    /// # Returns
    /// Hex-encoded string of the GTV-encoded transaction
    pub fn gvt_hex_encoded(&self) -> String {
        let gtv_e = gtv::encode_tx(self);
        
        hex::encode(gtv_e)
    }

    /// Computes the unique identifier (RID) of this transaction.
    /// 
    /// The transaction RID is computed by hashing the GTV representation
    /// of the transaction using the GTX hash function.
    /// 
    /// # Returns
    /// A fixed-size 32 bytes containing the transaction RID
    pub fn tx_rid(&self) -> Result<[u8; 32], hasher::HashError> {
        let to_draw_gtx = gtv::to_draw_gtx(self);
        gtv_hash(to_draw_gtx, self.merkle_hash_version)
    }

    /// Returns the hex-encoded transaction RID.
    /// 
    /// This is a convenience method that returns the transaction RID
    /// as a hexadecimal string.
    /// 
    /// # Returns
    /// Hex-encoded string of the transaction RID
    pub fn tx_rid_hex(&self) -> Result<String, hasher::HashError> {
        Ok(hex::encode(self.tx_rid()?))
    }

    /// Signs the transaction using a raw private key string.
    /// 
    /// # Arguments
    /// * `private_key` - Private key as a string
    /// 
    /// # Returns
    /// Result indicating success or a secp256k1 error
    /// 
    /// # Errors
    /// Returns an error if the private key is invalid or signing fails
    pub fn sign_from_raw_priv_key(&mut self, private_key: &str) -> Result<(), secp256k1::Error> {
        let private_key_bytes = Vec::from_hex(private_key).map_err(|_| secp256k1::Error::InvalidSecretKey)?;
        let private_key = private_key_bytes.try_into().map_err(|_| secp256k1::Error::InvalidSecretKey)?;
        self.sign(&private_key)
    }

    /// Signs the transaction with multiple raw private key strings.
    ///
    /// This method iteratively signs the transaction with each provided
    /// private key string, enabling multi-signature transactions.
    ///
    /// # Arguments
    /// * `private_keys` - Slice of raw private key strings
    ///
    /// # Returns
    /// Result indicating success or a secp256k1 error
    ///
    /// # Errors
    /// Returns an error if any private key is invalid or signing fails
    pub fn multi_sign_from_raw_priv_keys(&mut self, private_keys: &[&str]) -> Result<(), secp256k1::Error> {
        let private_keys_bytes: Vec<[u8; 32]> = private_keys
            .iter()
            .map(|private_key_hex| {
                let private_key_bytes = Vec::from_hex(private_key_hex).map_err(|_| secp256k1::Error::InvalidSecretKey)?;
                private_key_bytes.try_into().map_err(|_| secp256k1::Error::InvalidSecretKey)
            })
            .collect::<Result<Vec<[u8; 32]>, secp256k1::Error>>()?;

        let private_keys_refs: Vec<&[u8; 32]> = private_keys_bytes.iter().collect();

        self.multi_sign(private_keys_refs.as_slice())
    }

    /// Signs the transaction using a private key.
    /// 
    /// This method:
    /// 1. Derives the public key from the private key
    /// 2. Adds the public key to the signers list
    /// 3. Signs the transaction RID
    /// 4. Adds the signature to the signatures list
    /// 
    /// # Arguments
    /// * `private_key` - 32-byte private key
    /// 
    /// # Returns
    /// Result indicating success or a secp256k1 error
    /// 
    /// # Errors
    /// Returns an error if the private key is invalid or signing fails
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), secp256k1::Error> {
        let public_key = get_public_key(private_key)?;

        self.signers.get_or_insert_with(Vec::new).push(public_key.to_vec());

        let digest = self.tx_rid().map_err(|_| secp256k1::Error::InvalidMessage)?;
        let signature = sign(&digest, private_key)?;

        self.signatures.get_or_insert_with(Vec::new).push(signature.to_vec());

        Ok(())
    }

    /// Signs the transaction with multiple private keys.
    /// 
    /// This method iteratively signs the transaction with each provided
    /// private key, enabling multi-signature transactions.
    /// 
    /// # Arguments
    /// * `private_keys` - Slice of 32-byte private keys
    /// 
    /// # Returns
    /// Result indicating success or a secp256k1 error
    /// 
    /// # Errors
    /// Returns an error if any private key is invalid or signing fails
    pub fn multi_sign(&mut self, private_keys: &[&[u8; 32]]) -> Result<(), secp256k1::Error> {
        let public_keys = get_public_keys(private_keys)?;

        self.signers.get_or_insert_with(Vec::new).extend(public_keys.iter().map(|pk| pk.to_vec()));

        let digest = self.tx_rid().map_err(|_| secp256k1::Error::InvalidMessage)?;

        for private_key in private_keys {
             let signature = sign(&digest, private_key)?;
             self.signatures.get_or_insert_with(Vec::new).push(signature.to_vec());
        }

        Ok(())
    }

    /// Decodes a hexadecimal string representation of a transaction confirmation proof
    /// into a `TransactionConfirmationProofData` struct.
    ///
    /// This function is used to parse the proof data received from the blockchain
    /// to verify the inclusion of a transaction in a block. The input `proof`
    /// is expected to be a hex-encoded GTV (Generic Tree Value) structure
    /// representing the confirmation proof.
    ///
    /// # Arguments
    /// * `proof` - A string slice containing the hex-encoded confirmation proof data.
    ///
    /// # Returns
    /// A `Result` which is:
    /// - `Ok(TransactionConfirmationProofData)` if the proof is successfully decoded and
    ///   parsed into the `TransactionConfirmationProofData` struct.
    /// - `Err(String)` if the input string is not valid hexadecimal, if the GTV
    ///   decoding fails, or if the decoded GTV structure does not match the
    ///   expected format for a `TransactionConfirmationProofData`.
    ///
    /// # Errors
    /// This function will return an error string if:
    /// - The `proof` string cannot be hex-decoded.
    /// - The decoded bytes cannot be successfully GTV-decoded.
    /// - The root of the GTV-decoded data is not a dictionary (`Op_Params::Dict`).
    /// - Any required field (`blockHeader`, `hash`, `txIndex`, `witness`, `merkleProofTree`)
    ///   is missing or has an incorrect type within the decoded GTV dictionary.
    ///
    /// # Examples
    /// ```
    /// use crate::utils::transaction::{Transaction, TransactionConfirmationProofData};
    /// use crate::utils::operation::Params as Op_Params;
    ///
    /// let proof_hex_encoded_data = "A48203AA308203A6308201230C0B626C6F636B486561646572A18201120482010EA582010A30820106A12204207A37DD331AC8FED64EEFCCA231B0F975DE7F4371CE5CA44105A5B117DF6DE251A1220420BAB0B26A302920A56F7FFB9428FA52A264657594624F12C73B1510BEB76EBCE1A12204209423052CE47270FB5ADE54B30F662AAB476BF26314680CD716C0EC1484EF5C63A308020601979ADDCE2EA306020400A926E1A0020500A48181307F30310C0B636F6E6669675F68617368A1220420C9A490594951ACBB668F05FE83287DB48CDD628811F9F5D3083BF087686C3BD4301A0C136D65726B6C655F686173685F76657273696F6EA303020102302E0C077072696D617279A123042102DD859FE30F3C6102B364A5FDEB3C8C3DA2B22F4E541015C3BEFDA753EC672E8E302A0C0468617368A1220420796D019516EB32366BAA60F08E73A78C94BBDCF9ED3724017AED6E9FC729AF923081830C0F6D65726B6C6550726F6F6654726565A570306EA303020167A303020101A3030201F6A530302EA303020165A303020100A1220420796D019516EB32366BAA60F08E73A78C94BBDCF9ED3724017AED6E9FC729AF92A52B3029A303020164A12204200000000000000000000000000000000000000000000000000000000000000000300E0C077478496E646578A303020100308201B90C077769746E657373A18201AC048201A800000004000000210202F6F59D4F007C52FB84FAF3B3E02CF7B8F9C2A4B953618047DBA2C85A17854F00000040D056BADD7014B638DB4FF06E2D86D570FF1FE712B00833FCA9D175BC926502A7613A7CDD1DA50326F9AEA3BBF94CD4043191E02CE5A4F0D81071B14CF841FD770000002102EF6254CCADB304E39244858F3E506EF58816A2769E019AD11C35842862D981F80000004062E6FD188816B85538A76990E2EE943CBDC40C161CA98A87B5B070FEDF7946CF73A6BEFB5C3F0DC3F664F52D8A53C8B79C52ADC023276F9836739FE0301BABA70000002103C146E1860AACC77EBF3B5741D04CFFBC316B37921D4029CAF2479AF5F2D573EA00000040EAD69772A61F5FA1B5C71A977D98F88B57702A6CA005D39BD72CC5064FE1B48F3C49B1CECDE24F8F6620CF2CB679314477BD96644E717C4B2F657DC7F7EEB6FB0000002102DD859FE30F3C6102B364A5FDEB3C8C3DA2B22F4E541015C3BEFDA753EC672E8E00000040D994B3945F0AF229FBC7FB3A480CA10357E8F58076BB0F375CCE6044FE36996F4755F9B5C7AA11894DBDE9AFA734E05B4501614692480820A28D52DB04F577F7";
    /// let result = Transaction::confirmation_proof(proof_hex_encoded_data);
    ///
    /// assert!(result.is_ok());
    /// let proof_data = result.unwrap();
    /// assert_eq!(proof_data.tx_index, 0);
    /// // Further assertions can be made on other fields
    /// ```
    pub fn confirmation_proof(proof: &str) -> Result<TransactionConfirmationProofData, String> {
        let hex_decode_data = hex::decode(proof).map_err(|_| "Invalid hex".to_string())?;
        let result = gtv_decode(&hex_decode_data).map_err(|_| "GTV decode failed".to_string())?;

        if let Op_Params::Dict(ref confirmation_proof) = result {
            let block_header = extract_field!(confirmation_proof, "blockHeader", Op_Params::ByteArray, "blockHeader").to_vec();
            let hash = extract_field!(confirmation_proof, "hash", Op_Params::ByteArray, "hash").to_vec();
            let tx_index = *extract_field!(confirmation_proof, "txIndex", Op_Params::Integer, "txIndex");
            let witness = extract_field!(confirmation_proof, "witness", Op_Params::ByteArray, "witness").to_vec();
            let merkle_proof_tree = match confirmation_proof.get("merkleProofTree") {
                Some(Op_Params::Array(arr)) => arr.clone(),
                _ => return Err("Missing or invalid field: merkleProofTree".to_string()),
            };

            Ok(TransactionConfirmationProofData {
                block_header,
                hash,
                tx_index,
                witness,
                merkle_proof_tree,
            })
        } else {
            Err("Invalid proof data".to_string())
        }
    }

    /// Creates a new `Transaction` (or `Self`) instance from a raw hexadecimal string.
    ///
    /// This function is responsible for decoding a hexadecimal string representing transaction
    /// data into a structured format, likely using a custom Generalized Transaction Value (GTV)
    /// encoding scheme. It extracts key components such as the blockchain's Root ID (RID),
    /// operations, signers, and signatures from the decoded data.
    ///
    /// # Arguments
    ///
    /// * `tx` - A string slice (`&str`) containing the raw transaction data encoded in hexadecimal format.
    ///
    /// # Returns
    ///
    /// A `Result<Self, String>` which is:
    /// - `Ok(Self)`: If the hexadecimal string is successfully decoded and parsed into a valid
    ///   `Transaction` (or `Self`) instance.
    /// - `Err(String)`: If any error occurs during the process, such as:
    ///   - The input `tx` string is not valid hexadecimal.
    ///   - The decoded data fails to conform to the expected GTV structure.
    ///   - Specific components (like `block_chain_rid`, `operations`, `signers`, or `signatures`)
    ///     are missing or are of an unexpected type within the GTV structure.
    ///
    /// # Errors
    ///
    /// This function can return an error string in the following scenarios:
    /// - "Invalid hex": If `hex::decode` fails to parse the input `tx` string.
    /// - "GTV decode failed": If `gtv_decode` encounters an error during the GTV deserialization process.
    /// - Panics with "Unexpected signer type": (This is a current panic, ideally this would be
    ///   converted to a `Result::Err` for robust error handling in a production system).
    ///   This occurs if an element within the expected signers array is not a `ByteArray`.
    /// - Other potential errors related to unexpected data structures within the GTV `result`
    ///   (e.g., if `val2[0]` or `val2[2]` are not arrays as expected).
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Assuming `Transaction` is the type `Self` refers to, and `gtv_decode` and `hex` are available.
    /// // Also assuming a valid hex string for a transaction.
    ///
    /// // Example of a successful decode (conceptual, as actual hex depends on your GTV structure)
    /// let valid_hex_tx = "010203..."; // Replace with a real valid hex transaction string
    /// match Transaction::from_raw_data(valid_hex_tx) {
    ///     Ok(transaction) => {
    ///         println!("Successfully decoded transaction: {:?}", transaction);
    ///         // Further assertions or usage of the transaction object
    ///     },
    ///     Err(e) => {
    ///         eprintln!("Failed to decode transaction: {}", e);
    ///     }
    /// }
    ///
    /// // Example of an invalid hex string
    /// let invalid_hex_tx = "not_a_hex_string";
    /// if let Err(e) = Transaction::from_raw_data(invalid_hex_tx) {
    ///     assert_eq!(e, "Invalid hex");
    /// }
    ///
    /// // Example of a hex string that decodes but has invalid GTV structure
    /// let malformed_gtv_hex = "0a0b0c..."; // Replace with a hex string that causes GTV decode or structural errors
    /// if let Err(e) = Transaction::from_raw_data(malformed_gtv_hex) {
    ///     assert!(e.contains("GTV decode failed") || e.contains("Unexpected"));
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function currently panics if an element within the expected signers array is not
    /// of the `OpParams::ByteArray` type. For production-grade code, this panic should
    /// ideally be converted into a `Result::Err` for more graceful error handling.
    ///
    /// # Implementation Details
    ///
    /// 1. Decodes the input hexadecimal string `tx` into a byte vector.
    /// 2. Deserializes the byte vector into a `Params` object using `gtv_decode`.
    /// 3. Extracts the `block_chain_rid` from the first element of the main GTV array.
    /// 4. Iterates through the third element of the main GTV array to parse `signers`,
    ///    expecting each signer to be a `ByteArray`.
    /// 5. (Further logic for `operations` and `signatures` would be described here if visible).
    ///
    /// This function relies on the `hex` crate for hexadecimal decoding and a custom
    /// `gtv_decode` function for Generalized Transaction Value (GTV) deserialization.
    /// The `OpParams` enum is crucial for interpreting the structure of the decoded GTV data.
    pub fn from_raw_data(tx: &str) -> Result<Self, String> {
        let hex_decode_data = hex::decode(tx).map_err(|_| "Invalid hex".to_string())?;
        let result = gtv_decode(&hex_decode_data).map_err(|_| "GTV decode failed".to_string())?;

        let mut blockchain_rid = vec![];
        let mut operations: Vec<Operation> = vec![];
        let mut signers: Option<Vec<Vec<u8>>> = None;
        let mut signatures: Option<Vec<Vec<u8>>> = None;

        if let Op_Params::Array(val) = result {
            if let Op_Params::Array(val2) = &val[0] {
                // Blockchain RID
                blockchain_rid = val2[0].clone().to_vec();

                // Signers
                if let Op_Params::Array(val3) = &val2[2] {
                    if !val3.is_empty() {
                        signers = Some(val3.iter().map(|signer| signer.clone().to_vec()).collect());
                    }
                }

                // Operations
                if let Op_Params::Array(val3) = &val2[1]{
                    for operation in val3 {
                        if let Op_Params::Array(ops) = operation {
                            operations.push(Operation::from_list(ops[0].clone().to_string(), ops[1].clone().into()));
                        }
                    }
                }
            }

            // Signatures
            if let Op_Params::Array(val2) = &val[1] {
                if !val2.is_empty() {
                    signatures = Some(val2.iter().map(|signature| signature.clone().to_vec()).collect())
                }
            }
        }

        Ok(Self {
            blockchain_rid,
            operations: Some(operations),
            signers,
            signatures,
            ..Default::default()
        })
    }
}

/// Signs a message digest using ECDSA with secp256k1.
/// 
/// # Arguments
/// * `digest` - 32-byte message digest to sign
/// * `private_key` - 32-byte private key
/// 
/// # Returns
/// Result containing the 64-byte signature or a secp256k1 error
/// 
/// # Errors
/// Returns an error if the private key is invalid or signing fails
fn sign(digest: &[u8; 32], private_key: &[u8; 32]) -> Result<[u8; 64], secp256k1::Error> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array(*private_key)?;
    let message = Message::from_digest(*digest);
    let signature: Signature = secp.sign_ecdsa(message, &secret_key);
    let serialized_signature = signature.serialize_compact();
    Ok(serialized_signature)
}

/// Derives a public key from a private key using secp256k1.
/// 
/// # Arguments
/// * `private_key` - 32-byte private key
/// 
/// # Returns
/// Result containing the 33-byte compressed public key or a secp256k1 error
/// 
/// # Errors
/// Returns an error if the private key is invalid
fn get_public_key(private_key: &[u8; 32]) -> Result<[u8; 33], secp256k1::Error> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array(*private_key)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize();
    Ok(public_key)
}

/// Derives multiple public keys from a slice of private keys using secp256k1.
///
/// # Arguments
/// * `private_keys` - Slice of 32-byte private keys
///
/// # Returns
/// Result containing a vector of 33-byte compressed public keys or a secp256k1 error
///
/// # Errors
/// Returns an error if any private key is invalid
fn get_public_keys(private_keys: &[&[u8; 32]]) -> Result<Vec<[u8; 33]>, secp256k1::Error> {
    let mut public_keys = Vec::new();

    for private_key in private_keys {
        let public_key = get_public_key(private_key)?;
        public_keys.push(public_key);
    }

    Ok(public_keys)
}

#[test]
fn test_confirmation_proof() {
    let proof_hex_encoded_data = "A48203AA308203A6308201230C0B626C6F636B486561646572A18201120482010EA582010A30820106A12204207A37DD331AC8FED64EEFCCA231B0F975DE7F4371CE5CA44105A5B117DF6DE251A1220420BAB0B26A302920A56F7FFB9428FA52A264657594624F12C73B1510BEB76EBCE1A12204209423052CE47270FB5ADE54B30F662AAB476BF26314680CD716C0EC1484EF5C63A308020601979ADDCE2EA306020400A926E1A0020500A48181307F30310C0B636F6E6669675F68617368A1220420C9A490594951ACBB668F05FE83287DB48CDD628811F9F5D3083BF087686C3BD4301A0C136D65726B6C655F686173685F76657273696F6EA303020102302E0C077072696D617279A123042102DD859FE30F3C6102B364A5FDEB3C8C3DA2B22F4E541015C3BEFDA753EC672E8E302A0C0468617368A1220420796D019516EB32366BAA60F08E73A78C94BBDCF9ED3724017AED6E9FC729AF923081830C0F6D65726B6C6550726F6F6654726565A570306EA303020167A303020101A3030201F6A530302EA303020165A303020100A1220420796D019516EB32366BAA60F08E73A78C94BBDCF9ED3724017AED6E9FC729AF92A52B3029A303020164A12204200000000000000000000000000000000000000000000000000000000000000000300E0C077478496E646578A303020100308201B90C077769746E657373A18201AC048201A800000004000000210202F6F59D4F007C52FB84FAF3B3E02CF7B8F9C2A4B953618047DBA2C85A17854F00000040D056BADD7014B638DB4FF06E2D86D570FF1FE712B00833FCA9D175BC926502A7613A7CDD1DA50326F9AEA3BBF94CD4043191E02CE5A4F0D81071B14CF841FD770000002102EF6254CCADB304E39244858F3E506EF58816A2769E019AD11C35842862D981F80000004062E6FD188816B85538A76990E2EE943CBDC40C161CA98A87B5B070FEDF7946CF73A6BEFB5C3F0DC3F664F52D8A53C8B79C52ADC023276F9836739FE0301BABA70000002103C146E1860AACC77EBF3B5741D04CFFBC316B37921D4029CAF2479AF5F2D573EA00000040EAD69772A61F5FA1B5C71A977D98F88B57702A6CA005D39BD72CC5064FE1B48F3C49B1CECDE24F8F6620CF2CB679314477BD96644E717C4B2F657DC7F7EEB6FB0000002102DD859FE30F3C6102B364A5FDEB3C8C3DA2B22F4E541015C3BEFDA753EC672E8E00000040D994B3945F0AF229FBC7FB3A480CA10357E8F58076BB0F375CCE6044FE36996F4755F9B5C7AA11894DBDE9AFA734E05B4501614692480820A28D52DB04F577F7";
    let result = Transaction::confirmation_proof(proof_hex_encoded_data).unwrap();

    assert_eq!(result.tx_index, 0);

    let block_header_data = crate::utils::transaction::gtv::decode(&result.block_header).unwrap();

    if let crate::utils::operation::Params::Array(bhd) = block_header_data {
        assert_eq!(bhd[0].clone().to_hex_encode(), "7a37dd331ac8fed64eefcca231b0f975de7f4371ce5ca44105a5b117df6de251");
        assert_eq!(bhd[1].clone().to_hex_encode(), "bab0b26a302920a56f7ffb9428fa52a264657594624f12c73b1510beb76ebce1");
        assert_eq!(bhd[2].clone().to_hex_encode(), "9423052ce47270fb5ade54b30f662aab476bf26314680cd716c0ec1484ef5c63");
        if let crate::utils::operation::Params::Integer(int_val) = bhd[3] {
          assert_eq!(int_val, 1750649916974);
        }
    }

    assert_eq!(hex::encode(result.hash), "796d019516eb32366baa60f08e73a78c94bbdcf9ed3724017aed6e9fc729af92");
    assert_eq!(hex::encode(result.witness), "00000004000000210202f6f59d4f007c52fb84faf3b3e02cf7b8f9c2a4b953618047dba2c85a17854f00000040d056badd7014b638db4ff06e2d86d570ff1fe712b00833fca9d175bc926502a7613a7cdd1da50326f9aea3bbf94cd4043191e02ce5a4f0d81071b14cf841fd770000002102ef6254ccadb304e39244858f3e506ef58816a2769e019ad11c35842862d981f80000004062e6fd188816b85538a76990e2ee943cbdc40c161ca98a87b5b070fedf7946cf73a6befb5c3f0dc3f664f52d8a53c8b79c52adc023276f9836739fe0301baba70000002103c146e1860aacc77ebf3b5741d04cffbc316b37921d4029caf2479af5f2d573ea00000040ead69772a61f5fa1b5c71a977d98f88b57702a6ca005d39bd72cc5064fe1b48f3c49b1cecde24f8f6620cf2cb679314477bd96644e717c4b2f657dc7f7eeb6fb0000002102dd859fe30f3c6102b364a5fdeb3c8c3da2b22f4e541015c3befda753ec672e8e00000040d994b3945f0af229fbc7fb3a480ca10357e8f58076bb0f375cce6044fe36996f4755f9b5c7aa11894dbde9afa734e05b4501614692480820a28d52db04f577f7");

}

#[tokio::test]
async fn get_raw_transaction_data() {
    use crate::utils::operation::Params;
    use crate::transport::client::RestClient;
    use bigdecimal::FromPrimitive;

    let rc = RestClient{
        node_url: vec!["https://system.chromaway.com"],
        ..Default::default()
    };

    let blockchain_rid = "15C0CA99BEE60A3B23829968771C50E491BD00D2E3AE448580CD48A8D71E7BBA";
    let tx_rid = "B5AE42A1645992D74E955A17D90F275778A19ADD3EB68A90EB0DD7225641A43A";

    let result = rc.get_raw_transaction_data(blockchain_rid, tx_rid).await.unwrap();

    let ft4_evm_auth_ids = [
        "62a123cf432ec739d229d804b78a7c30d39ae29101247b1e4bfd1b20cc54cc43", // account_id
        "cc01ed41ea21a8f516742ebbf0a3a9927c5de8816ed2f289f03e6f1db8a4e8bd" // auth_descriptor_id
        ];

    let ft4_evm_auth_signatures = vec![
        Params::Array(vec![
            Params::ByteArray(hex::decode("d98116e2cb881ce13f0b70255549ca29420ef478af888db25a8b957d802af71d").unwrap()),
            Params::ByteArray(hex::decode("722750f833f40eccc701697835891f80fa90c1749b4eaaa059ec9c7a5017f977").unwrap()),
            Params::Integer(27)
        ])
    ];

    let nop = vec![
        Params::ByteArray(hex::decode("93C0AC18E20D1BACF3189E5BDE2F4B0F1367FC4CDFC2A3EB7168E17073EAE584").unwrap())
    ];

    let eif_hbridge_bridge_ft4_token_to_evm = vec![
        Params::Integer(1), // network_id
        Params::ByteArray(hex::decode("5f16d1545a0881f971b164f1601cbbf51c29efd0633b2730da18c403c3b428b5").unwrap()), // asset_id
        Params::BigInteger(num_bigint::BigInt::from_i128(63080704247).unwrap()), // amount
        Params::ByteArray(hex::decode("d1941a115536b619c4f528432237d35f79544cfe").unwrap()), // beneficiary
    ];

    if let Some(operations) = result.operations {
        for op in operations {
            if let Some("ft4.evm_auth") = op.operation_name.as_deref() {
                if let Some(ref val) = op.list {
                    for item in val {
                        if let Params::ByteArray(val2) = item {
                            assert!(ft4_evm_auth_ids.contains(&hex::encode(val2).as_str()));
                        }
                        if let Params::Array(val2) = item {
                            assert_eq!(val2, &ft4_evm_auth_signatures);
                        }
                    }
                }
            }
            if let Some("eif.hbridge.bridge_ft4_token_to_evm") = op.operation_name.as_deref() {
                if let Some(ref val) = op.list {
                    assert_eq!(val, &eif_hbridge_bridge_ft4_token_to_evm);
                }
            }
            if let Some("nop") = op.operation_name.as_deref() {
                assert_eq!(op.list, Some(nop.clone()));
            }
        }
    }
}

#[tokio::test]
async fn get_transactions_info() {
    use crate::transport::client::RestClient;

    let rc = RestClient{
        node_url: vec!["https://system.chromaway.com"],
        ..Default::default()
    };

    let blockchain_rid = "15C0CA99BEE60A3B23829968771C50E491BD00D2E3AE448580CD48A8D71E7BBA";
    let tx_rid = "B5AE42A1645992D74E955A17D90F275778A19ADD3EB68A90EB0DD7225641A43A";

    let transaction_info: TransactionInfo = rc.get_transactions_info(blockchain_rid, Some(tx_rid), None).await.unwrap();

    assert_eq!("BA543AEA864501373928F830AA4EE166FE215FC21F3176BF06B4454ADF45BC36", transaction_info.block_rid);
    assert_eq!(3042601, transaction_info.block_height);

    let transactions_info: Vec<TransactionInfo> = rc.get_transactions_info(blockchain_rid, None, Some(&vec![
        ("limit", "1"),
        // ("before-time", "1740659274153"),
        // ("after-time", "1740659274152"),
        // ("signer", "02FEA5C0D8396B38C50200F2A583DCC8ED23416B9F9700A4AA435D57865939A536")
    ])).await.unwrap();

    assert!(transactions_info[0].block_height > 0);

    let number_successful_transactions = rc.get_number_successful_transactions(blockchain_rid).await.unwrap();

    assert!(number_successful_transactions > 0);
}