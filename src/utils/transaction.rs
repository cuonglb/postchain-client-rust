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
use super::{hasher, operation::Operation};
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
pub struct Transaction<'a> {
    /// Unique identifier of the blockchain this transaction belongs to
    pub blockchain_rid: Vec<u8>,
    /// List of operations to be executed in this transaction
    pub operations: Option<Vec<Operation<'a>>>,
    /// List of public keys of the signers
    pub signers: Option<Vec<Vec<u8>>>,
    /// List of signatures corresponding to the signers
    pub signatures: Option<Vec<Vec<u8>>>,
    // Hash version (default is 1)
    pub merkle_hash_version: u8
}

impl<'a> Default for Transaction<'a> {
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

impl<'a> Transaction<'a> {
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
        operations: Option<Vec<Operation<'a>>>,
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
        let hex_encode = hex::encode(gtv_e);
        hex_encode
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
    let secret_key = SecretKey::from_slice(private_key)?;
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
    let secret_key = SecretKey::from_slice(private_key)?;
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