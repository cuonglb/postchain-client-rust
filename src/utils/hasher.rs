#![allow(warnings)]

//! Merkle tree-based hashing implementation for Generic Tree Value (GTV) data structures.
//! 
//! This module implements a specialized Merkle tree for hashing GTV data structures. It provides:
//! - Construction of Merkle trees from GTV data (arrays, dictionaries, and primitive values)
//! - Cryptographic hashing using SHA-256 with type-specific prefixes
//! - Deterministic hash computation for complex nested data structures
//! 
//! # Architecture
//! The implementation consists of three main components:
//! - `BinaryTreeNode`: The basic building block of the Merkle tree
//! - `BinaryTreeFactory`: Constructs Merkle trees from GTV data
//! - `MerkleHashCalculator`: Computes cryptographic hashes of the tree
//! 
//! # Hash Prefixes
//! Different node types use distinct prefixes to ensure unique hashes:
//! - Leaf nodes: 1 (for actual data)
//! - Internal nodes: 0 (for tree structure)
//! - Array nodes: 7 (for ordered sequences)
//! - Dictionary nodes: 8 (for key-value mappings)
//! 
//! # Examples
//! 
//! Hashing an array:
//! ```
//! use crate::utils::operation::Params;
//! 
//! let array_data = Params::Array(vec![
//!     Params::Text("foo".to_string()),
//!     Params::Text("bar".to_string())
//! ]);
//! 
//! let hash_version = 2;
//! let hash = gtv_hash(array_data, hash_version).unwrap();
//! ```
//! 
//! Hashing a dictionary:
//! ```
//! use std::collections::BTreeMap;
//! use crate::utils::operation::Params;
//! 
//! let mut dict = BTreeMap::new();
//! dict.insert("key".to_string(), Params::Integer(42));
//! let dict_data = Params::Dict(dict);
//! 
//! let hash_version = 1;
//! let hash = gtv_hash(dict_data, hash_version).unwrap();
//! ```
//! 
//! # Error Handling
//! The module uses `HashError` to handle error cases:
//! - `EmptyArray`: When processing an empty array structure
//! - `EmptyDict`: When processing an empty dictionary structure

use sha2::{Sha256, Digest};
use crate::utils::operation::Params;
use crate::encoding::gtv::encode_value as gtv_encode_value;
use secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, Message};

/// Represents different types of nodes in the Merkle tree structure.
/// 
/// Each node type serves a specific purpose in building and hashing the tree:
/// - `Node`: Regular internal nodes that combine and hash their children
/// - `Leaf`: Contains actual GTV data to be hashed
/// - `EmptyLeaf`: Used for padding incomplete trees (returns zero hash)
/// - `DictNode`: Special node for dictionaries with sorted key-value pairs
/// - `ArrayNode`: Special node for arrays preserving element order
/// 
/// The node type determines:
/// 1. How the node's hash is computed
/// 2. What prefix is used in the hash computation
/// 3. How child nodes are processed
#[derive(Clone, PartialEq, Debug)]
enum NodeType {
    /// Internal node with two children, uses prefix 0
    Node,
    /// Leaf node containing actual data, uses prefix 1
    Leaf,
    /// Empty leaf node for padding, returns zero hash
    EmptyLeaf,
    /// Dictionary node for key-value pairs, uses prefix 8
    DictNode,
    /// Array node for ordered elements, uses prefix 7
    ArrayNode,
}

/// Errors that can occur during Merkle tree construction and hashing.
/// 
/// These errors help identify issues with input data structures:
/// - `EmptyArray`: Indicates an attempt to process an invalid or empty array
/// - `EmptyDict`: Indicates an attempt to process an invalid or empty dictionary
/// 
/// # Example
/// ```
/// use crate::utils::operation::Params;
/// 
/// // Attempting to hash an empty array
/// let hash_version = 2;
/// let empty_array = Params::Array(vec![]);
/// match gtv_hash(empty_array, hash_version) {
///     Ok(_) => println!("Hash computed successfully"),
///     Err(HashError::EmptyArray(msg)) => println!("{}", msg),
///     _ => println!("Other error occurred"),
/// }
/// ```
#[derive(Clone, Debug)]
pub enum HashError {
    /// Error when processing an invalid or empty array
    EmptyArray(String),
    /// Error when processing an invalid or empty dictionary
    EmptyDict(String),
}

/// Represents a node in the binary Merkle tree.
/// 
/// A `BinaryTreeNode` is the fundamental building block of the Merkle tree structure.
/// Each node can be:
/// - An internal node (Node, ArrayNode, or DictNode) with left and right children
/// - A leaf node containing a GTV value
/// - An empty leaf node used for padding incomplete trees
/// 
/// The node's behavior during hash computation is determined by its `type_of_node` field,
/// which specifies what prefix to use and how to process child nodes.
/// 
/// # Node Structure
/// - `left`: Left child node (for internal nodes)
/// - `right`: Right child node (for internal nodes)
/// - `value`: Stored GTV value (for leaf nodes)
/// - `type_of_node`: Determines the node's role and hash computation method
#[derive(Clone, Debug)]
struct BinaryTreeNode {
    /// Left child of the node
    left: Option<Box<BinaryTreeNode>>,
    /// Right child of the node
    right: Option<Box<BinaryTreeNode>>,
    /// Value stored in the node (for leaf nodes)
    value: Option<Box<Params>>,
    /// Type of the node (internal, leaf, empty, etc.)
    type_of_node: NodeType
}

impl Default for BinaryTreeNode {
    fn default() -> Self {
        BinaryTreeNode {
            left: None,
            right: None,
            value: None,
            type_of_node: NodeType::EmptyLeaf,
        }
    }
}

impl BinaryTreeNode {
    /// Creates a new internal node with specified children, value, and type.
    /// 
    /// # Arguments
    /// * `left` - Left child node
    /// * `right` - Right child node
    /// * `value` - Optional value stored in the node
    /// * `type_of_node` - Type of the node
    fn new_node(left: Option<Box<BinaryTreeNode>>, right: Option<Box<BinaryTreeNode>>, value: Option<Box<Params>>, type_of_node: NodeType) -> Self {
        BinaryTreeNode {
            left, right, value, type_of_node
        }
    }

    /// Creates a new leaf node with an optional value.
    /// 
    /// # Arguments
    /// * `value` - Optional value to store in the leaf
    /// * `is_empty_leaf` - If true, creates an empty leaf node
    fn new_leaf(value: Option<Box<Params>>, is_empty_leaf: bool) -> Box<Self> {
        let type_of_node = match is_empty_leaf {
            true => NodeType::EmptyLeaf,
            false => NodeType::Leaf,
        };

        Box::new(BinaryTreeNode {
            value, type_of_node, ..Default::default()
        })
    }
}

/// Factory for creating binary Merkle trees from GTV data structures.
#[derive(Clone, Debug)]
struct BinaryTreeFactory;

impl BinaryTreeFactory {
    /// Processes a layer of nodes in the Merkle tree construction.
    /// 
    /// This function implements the core Merkle tree building logic by:
    /// 1. Taking pairs of nodes and combining them into parent nodes
    /// 2. Recursively processing layers until a single root node is formed
    /// 3. Handling odd numbers of nodes by promoting the last unpaired node
    /// 
    /// # Arguments
    /// * `leaves` - Vector of nodes to process into a tree layer
    /// 
    /// # Returns
    /// * `Ok(Box<BinaryTreeNode>)` - The root node of the processed layer
    /// * `Err(HashError::EmptyArray)` - If the input vector is empty
    /// 
    /// # Note
    /// When processing an odd number of nodes, the last node is promoted to the next layer without a pair
    fn process_layer(leaves: Vec<Box<BinaryTreeNode>>) -> Result<Box<BinaryTreeNode>, HashError> {
        if leaves.is_empty() {
            return Err(HashError::EmptyArray("Cannot process empty layer of nodes".to_string()));
        }

        if leaves.len() == 1 {
            return Ok(leaves.into_iter().next().unwrap());
        }

        let mut next_layer = Vec::with_capacity((leaves.len() + 1) / 2);
        let mut iter = leaves.into_iter();

        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                next_layer.push(Box::new(BinaryTreeNode::new_node(
                    Some(left),
                    Some(right),
                    None,
                    NodeType::Node
                )));
            } else {
                next_layer.push(left);
            }
        }

        Self::process_layer(next_layer)
    }

    /// Processes an array parameter into a Merkle tree node.
    /// 
    /// Creates a tree structure from an array of values, with array-specific
    /// hash prefixes (7) for the nodes. Handles special cases:
    /// - Empty arrays get two empty leaf children
    /// - Single-element arrays get an empty right child
    /// 
    /// # Arguments
    /// * `params` - Box containing array parameters to process
    /// * `hash_version` - Hash version
    /// 
    /// # Returns
    /// * `Ok(Box<BinaryTreeNode>)` - A tree node representing the array structure
    /// * `Err(HashError::EmptyArray)` - If the input is not a valid array parameter
    /// 
    /// # Note
    /// The resulting tree preserves the order of array elements in the leaf nodes
    fn process_array_node(params: Box<Params>, hash_version: u8) -> Result<Box<BinaryTreeNode>, HashError> {
        if let Params::Array(array_value) = *params {
            if array_value.is_empty() {
                let left = BinaryTreeNode::new_leaf(None, true);
                let right = BinaryTreeNode::new_leaf(None, true);
                let value = Box::new(Params::Array(Vec::new()));
                return Ok(Box::new(BinaryTreeNode::new_node(Some(left), Some(right), Some(value), NodeType::ArrayNode)));
            }

            if hash_version == 1 && array_value.len() == 1 {
                let av = array_value[0].clone();

                if let Params::Array(_) = av {
                    return Self::build_tree(Box::new(av), hash_version);
                }

                if let Params::Dict(_) = av {
                    return Self::build_tree(Box::new(Params::Array(av.dict_to_array())), hash_version);
                }
            }

            let leaves: Result<Vec<_>, _> = array_value
                .iter()
                .map(|value| Box::new(value.clone()))
                .map(|params| Self::build_tree(params, hash_version))
                .collect();

            let leaves = leaves?;

            let value = Box::new(Params::Array(array_value.clone()));

            let tree_root = if leaves.len() == 1 {
                let left = leaves.into_iter().next().unwrap();
                let right = BinaryTreeNode::new_leaf(None, true);
                BinaryTreeNode::new_node(Some(left), Some(right), None, NodeType::Node)
            } else {
                *Self::process_layer(leaves)?
            };

            let node = BinaryTreeNode::new_node(tree_root.left, tree_root.right, Some(value), NodeType::ArrayNode);
            Ok(Box::new(node))
        } else {
            Err(HashError::EmptyArray("Invalid array parameter provided".to_string()))
        }
    }

    /// Processes a dictionary parameter into a Merkle tree node.
    /// 
    /// Creates a tree structure from dictionary key-value pairs, with
    /// dictionary-specific hash prefixes (8) for the nodes. Special handling:
    /// - Empty dictionaries get two empty leaf children
    /// - Keys and values are stored as alternating leaf nodes
    /// - Keys are stored as Text parameters
    /// 
    /// # Arguments
    /// * `params` - Box containing dictionary parameters to process
    /// * `hash_version` - Hash version
    /// 
    /// # Returns
    /// * `Ok(Box<BinaryTreeNode>)` - A tree node representing the dictionary structure
    /// * `Err(HashError::EmptyDict)` - If the input is not a valid dictionary parameter
    /// 
    /// # Note
    /// Dictionary entries are processed in sorted order by key to ensure consistent hashing
    fn process_dict_node(params: Box<Params>, hash_version: u8) -> Result<Box<BinaryTreeNode>, HashError> {
        if let Params::Dict(dict_value) = *params {
            if dict_value.is_empty() {
                let left = BinaryTreeNode::new_leaf(None, true);
                let right = BinaryTreeNode::new_leaf(None, true);
                let value = Box::new(Params::Dict(std::collections::BTreeMap::new()));
                return Ok(Box::new(BinaryTreeNode::new_node(Some(left), Some(right), Some(value), NodeType::DictNode)));
            }

            let leaves: Result<Vec<_>, _> = dict_value
                .iter()
                .flat_map(|(key, value)| {
                    let key_leaf = BinaryTreeNode::new_leaf(Some(Box::new(Params::Text(key.clone()))), false);
                    let value_tree = Self::build_tree(Box::new(value.clone()), hash_version);
                    match value_tree {
                        Ok(tree) => vec![Ok(key_leaf), Ok(tree)],
                        Err(err) => vec![Err(err)],
                    }
                })
                .collect();

            let leaves = leaves?;
            let value = Box::new(Params::Dict(dict_value.clone()));

            let tree_root = if leaves.len() == 1 {
                let left = leaves.into_iter().next().unwrap();
                let right = BinaryTreeNode::new_leaf(None, true);
                BinaryTreeNode::new_node(Some(left), Some(right), None, NodeType::Node)
            } else {
                *Self::process_layer(leaves)?
            };

            let node = BinaryTreeNode::new_node(tree_root.left, tree_root.right, Some(value), NodeType::DictNode);
            Ok(Box::new(node))
        } else {
            Err(HashError::EmptyDict("Invalid dictionary parameter provided".to_string()))
        }
    }

    /// Builds a complete Merkle tree from a parameter value.
    /// 
    /// Recursively processes the input parameter based on its type:
    /// - Arrays are processed into ArrayNode trees
    /// - Dictionaries are processed into DictNode trees
    /// - Other values become leaf nodes
    /// 
    /// # Arguments
    /// * `params` - Box containing the parameter to process into a tree
    /// * `hash_version` - Hash version
    /// 
    /// # Returns
    /// * `Ok(Box<BinaryTreeNode>)` - The root node of the complete Merkle tree
    /// * `Err(HashError)` - If processing fails due to invalid input
    /// 
    /// # Note
    /// The resulting tree structure preserves the semantic structure of the input data
    fn build_tree(params: Box<Params>, hash_version: u8) -> Result<Box<BinaryTreeNode>, HashError> {
        match *params {
            Params::Array(_) =>
                Self::process_array_node(params, hash_version),
            Params::Dict(_) =>
                Self::process_dict_node(params, hash_version),
            _ =>
                Ok(BinaryTreeNode::new_leaf(Some(params), false))
        }
    }
}

/// Calculator for computing Merkle tree hashes using SHA-256.
struct MerkleHashCalculator;

const HASH_PREFIX_LEAF: u8 = 1;
const HASH_PREFIX_NODE: u8 = 0;
const HASH_PREFIX_NODE_ARRAY: u8 = 7;
const HASH_PREFIX_NODE_DICT: u8 = 8;

impl MerkleHashCalculator {
    /// Computes SHA-256 hash of input data.
    /// 
    /// Uses the SHA-256 algorithm to create a cryptographic hash
    /// of the input data bytes.
    /// 
    /// # Arguments
    /// * `data` - Slice of bytes to hash
    /// 
    /// # Returns
    /// A fixed-size array containing the 32-byte SHA-256 hash value
    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Calculates hash for a leaf node.
    /// 
    /// Creates a hash for a leaf node by:
    /// 1. Prepending the leaf prefix (1)
    /// 2. GTV-encoding the parameter value
    /// 3. Computing SHA-256 of the combined bytes
    /// 
    /// # Arguments
    /// * `value` - Optional parameter value to hash. Must be Some for non-empty leaves
    /// 
    /// # Returns
    /// A fixed-size array containing the 32-byte hash of the leaf node
    /// 
    /// # Note
    /// The leaf prefix ensures leaf node hashes are distinct from internal node hashes
    fn calculate_leaf_hash(value: &Params) -> [u8; 32] {
        let gev = gtv_encode_value(value);
        let mut buffer = Vec::with_capacity(1 + gev.len());
        buffer.push(HASH_PREFIX_LEAF);
        buffer.extend_from_slice(&gev);
        Self::sha256(&buffer)
    }

    /// Calculates hash for an internal node.
    /// 
    /// Creates a hash for an internal node by:
    /// 1. Prepending the node type prefix
    /// 2. Concatenating left and right child hashes
    /// 3. Computing SHA-256 of the combined bytes
    /// 
    /// # Arguments
    /// * `has_prefix` - Node type prefix:
    ///   - 0 for regular internal nodes
    ///   - 7 for array nodes
    ///   - 8 for dictionary nodes
    /// * `left` - 32-byte hash of the left child
    /// * `right` - 32-byte hash of the right child
    /// 
    /// # Returns
    /// A fixed-size array containing the 32-byte hash of the internal node
    /// 
    /// # Note
    /// Different prefixes ensure unique hashes for different node types
    fn calculate_node_hash(has_prefix: u8, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut buffer = [0u8; 65];
        buffer[0] = has_prefix;
        buffer[1..33].copy_from_slice(&left);
        buffer[33..].copy_from_slice(&right);
        Self::sha256(&buffer)
    }

    /// Recursively calculates the Merkle hash of a tree node.
    /// 
    /// Traverses the tree structure and computes hashes according to node types:
    /// - Empty leaves return a zero hash
    /// - Regular leaves are hashed with prefix 1
    /// - Array nodes are hashed with prefix 7
    /// - Dictionary nodes are hashed with prefix 8
    /// - Other internal nodes are hashed with prefix 0
    /// 
    /// # Arguments
    /// * `btn` - Root node of the tree or subtree to hash
    /// 
    /// # Returns
    /// A fixed-size array containing the 32-byte Merkle hash of the tree/subtree
    /// 
    /// # Note
    /// The hash computation preserves the structural properties of the tree
    fn calculate_merkle_hash(btn: &BinaryTreeNode) -> [u8; 32] {
        match &btn.type_of_node {
            NodeType::EmptyLeaf => [0; 32],
            NodeType::Leaf => Self::calculate_leaf_hash(btn.value.as_ref().unwrap()),
            NodeType::ArrayNode | NodeType::DictNode | NodeType::Node => {
                let has_prefix = match btn.type_of_node {
                    NodeType::ArrayNode => HASH_PREFIX_NODE_ARRAY,
                    NodeType::DictNode => HASH_PREFIX_NODE_DICT,
                    _ => HASH_PREFIX_NODE,
                };
                let left_hash = btn.left.as_ref().map(|left| Self::calculate_merkle_hash(left)).unwrap_or([0; 32]);
                let right_hash = btn.right.as_ref().map(|right| Self::calculate_merkle_hash(right)).unwrap_or([0; 32]);

                Self::calculate_node_hash(has_prefix, left_hash, right_hash)
            }
        }
    }
}

/// Computes a cryptographic hash of a GTV (Generic Tree Value) parameter using a Merkle tree.
/// 
/// This function:
/// 1. Constructs a Merkle tree from the input GTV data
/// 2. Computes SHA-256 hashes for each node with type-specific prefixes
/// 3. Combines hashes up the tree to produce a final 32-byte hash
/// 
/// The hashing process ensures:
/// - Unique hashes for different data structures
/// - Order preservation for arrays
/// - Consistent hashing for dictionaries (using sorted keys)
/// - Distinct representations for different node types via prefixes
/// 
/// # Arguments
/// * `value` - GTV parameter to hash (can be array, dictionary, or primitive value)
/// 
/// # Returns
/// * `Ok([u8; 32])` - A fixed-size array 32-byte SHA-256 hash of the parameter
/// * `Err(HashError)` - If processing fails due to invalid input
/// 
/// # Examples
/// 
/// Hashing primitive values:
/// ```
/// use crate::utils::operation::Params;
/// 
/// let hash_version = 2;
/// 
/// // Hash an integer
/// let int_hash = gtv_hash(Params::Integer(42), hash_version).unwrap();
/// 
/// // Hash a string
/// let text_hash = gtv_hash(Params::Text("hello".to_string()), hash_version).unwrap();
/// ```
/// 
/// Hashing nested structures:
/// ```
/// use std::collections::BTreeMap;
/// use crate::utils::operation::Params;
/// 
/// // Create a nested structure
/// let mut dict = BTreeMap::new();
/// dict.insert("array".to_string(), Params::Array(vec![
///     Params::Integer(1),
///     Params::Text("two".to_string())
/// ]));
/// let data = Params::Dict(dict);
/// 
/// // Compute hash
/// let hash_version = 2;
/// let hash = gtv_hash(data, hash_version).unwrap();
/// ```
pub fn gtv_hash(value: Params, hash_version: u8) -> Result<[u8; 32], HashError> {
    let tree = BinaryTreeFactory::build_tree(Box::new(value), hash_version)?;
    Ok(MerkleHashCalculator::calculate_merkle_hash(&tree))
}

/// Verifies an ECDSA signature against a compressed secp256k1 public key and a message hash.
///
/// This function is designed for common cryptographic verification tasks, specifically
/// handling 33-byte compressed public keys, 64-byte compact signatures, and 32-byte
/// message hashes (e.g., SHA-256 or Keccak-256 outputs).
///
/// # Arguments
///
/// * `pubkey_bytes` - A 33-byte array (`[u8; 33]`) representing the **compressed**
///   secp256k1 public key (prefix 0x02 or 0x03 followed by the X-coordinate).
/// * `signature_bytes` - A 64-byte array (`[u8; 64]`) representing the signature
///   in **compact (R, S) format** (32 bytes R, 32 bytes S).
/// * `hashed_data_bytes` - A 32-byte array (`[u8; 32]`) representing the **message hash**
///   that was signed.
///
/// # Returns
///
/// * `Ok(true)`: The signature is valid for the given public key and message hash.
/// * `Ok(false)`: The signature is invalid (the verification check failed, typically
///   an `IncorrectSignature` error from the underlying library).
/// * `Err(secp256k1::Error)`: An error occurred during input parsing (e.g., invalid
///   public key format, invalid signature format) or an internal library error.
///
/// # Errors
///
/// Returns an error if any of the input byte slices cannot be successfully converted
/// into their respective secp256k1 types (`PublicKey`, `Signature`, `Message`).
/// Note that a verification failure is captured as `Ok(false)`, not an `Err`.
pub fn verify_signature(pubkey_bytes: [u8;33], signature_bytes: [u8;64], hashed_data_bytes: [u8; 32]) -> Result<bool, secp256k1::Error> {
    let public_key = PublicKey::from_slice(&pubkey_bytes)?;
    let signature = Signature::from_compact(&signature_bytes)?;
    let message = Message::from_slice(&hashed_data_bytes)?;

    let secp = Secp256k1::verification_only();

    match secp.verify_ecdsa(message, &signature, &public_key) {
        Ok(_) => Ok(true),
        Err(secp256k1::Error::IncorrectSignature) => Ok(false),
        Err(err) => Err(err),
    }
}

#[test]
fn test_gtv_hash() {
    use std::collections::BTreeMap;

    let data1 = Params::Array(vec![
        Params::Text("foo".to_string()), Params::Array(vec![
            Params::Text("bar2".to_string()), Params::Text("bar2".to_string())
        ])
    ]);

    let mut data2_btree: BTreeMap<String, Params> = BTreeMap::new();
    data2_btree.insert("foo".to_string(), Params::Integer(-1));
    data2_btree.insert("foo1".to_string(), Params::Text("OK".to_string()));
    data2_btree.insert("bar".to_string(), Params::BigInteger(i128::MAX.into()));
    data2_btree.insert("bar1".to_string(), Params::BigInteger((1000000000000 as i128).into()));

    let data2 = Params::Dict(data2_btree);
    
    let result1 = gtv_hash(data1, 2).unwrap();
    let result2 = gtv_hash(data2, 2).unwrap();

    assert_eq!("6357d3200e0dfb1bce5f3eb789714842747b39810248f83dba6382c7e7020e20", hex::encode(result1));
    assert_eq!("9f3d80d08a942b86e20932ad74356703dba7ba78b792f2d6ad93201ab9a71bab", hex::encode(result2));
}

#[test]
fn test_gtv_hash_v1() {
    let data1 = Params::Array(vec![Params::Text("a".to_string())]);
    let data2 = Params::Array(vec![Params::Array(vec![Params::Text("a".to_string())])]);
    let data3 = Params::Array(vec![
        Params::Array(vec![
            Params::Array(vec![Params::Text("a".to_string())])
            ])
        ]);

    let result1 = gtv_hash(data1, 1).unwrap();
    let result2 = gtv_hash(data2, 1).unwrap();
    let result3 = gtv_hash(data3, 1).unwrap();

    let expected_hash_result = "5ad2414edcd34b9a8bdc22921b8a1b8cef6cab04115dd0e7eb000b05353b315a";

    assert_eq!(hex::encode(result1), expected_hash_result);
    assert_eq!(hex::encode(result2), expected_hash_result);
    assert_eq!(hex::encode(result3), expected_hash_result);
}

#[test]
fn test_gtv_hash_v2() {
    let data1 = Params::Array(vec![Params::Text("a".to_string())]);
    let data2 = Params::Array(vec![Params::Array(vec![Params::Text("a".to_string())])]);
    let data3 = Params::Array(vec![
        Params::Array(vec![
            Params::Array(vec![Params::Text("a".to_string())])
            ])
        ]);

    let result1 = gtv_hash(data1, 2).unwrap();
    let result2 = gtv_hash(data2, 2).unwrap();
    let result3 = gtv_hash(data3, 2).unwrap();

    assert_eq!(hex::encode(result1), "5ad2414edcd34b9a8bdc22921b8a1b8cef6cab04115dd0e7eb000b05353b315a");
    assert_eq!(hex::encode(result2), "19605d1044cc20248e315f98f2d4c4aa7adfe6861607a0d000641837c3b962f8");
    assert_eq!(hex::encode(result3), "574b45c58e62ff7b786ee644579ffea593c89541498c1692fb8c99d811265166");
}

#[test]
fn test_gtv_hash_v1_and_v2_of_array_of_dicts() {
    let data = Params::Array(vec![
        Params::Dict(std::collections::BTreeMap::from([
            ("a".to_string(), Params::Text("b".to_string())),
            ("c".to_string(), Params::Text("d".to_string()))
        ]))
    ]);

    let hash_v1_result = "891cdf10ff613a90899ff0ffe1a515d8ed74fe71e36249f0b6dd175eec70805d";
    let hash_v2_result = "9d2f6cfa72538e24584363ada5882c2be3f83d75aff598d0009330db22d961ff";

    let result = gtv_hash(data.clone(), 1).unwrap();
    assert_eq!(hex::encode(result), hash_v1_result);

    let result = gtv_hash(data, 2).unwrap();
    assert_eq!(hex::encode(result), hash_v2_result);

    let a1 =  Params::Dict(std::collections::BTreeMap::from([
        ("a1".to_string(), Params::Text("b".to_string()))
    ]));
    let c1 =  Params::Dict(std::collections::BTreeMap::from([
        ("c1".to_string(), Params::Text("d".to_string()))
    ]));

    let data = Params::Array(vec![
        Params::Dict(std::collections::BTreeMap::from([
            ("a".to_string(), a1),
            ("c".to_string(), c1)
        ]))
    ]);

    let hash_v1_result = "132fc201e78c96fc2c563a6cff21fa12e45815871e34a267b72c41c0fe48f410";
    let hash_v2_result = "ea56d66de794ad212183de103aca17df8eec177bf299ff203cc0aeb287a76495";

    let result = gtv_hash(data.clone(), 1).unwrap();
    assert_eq!(hex::encode(result), hash_v1_result);

    let result = gtv_hash(data, 2).unwrap();
    assert_eq!(hex::encode(result), hash_v2_result);
}

#[test]
fn test_success_verify_signature() {
    let sample_pubkey = "0350fe40766bc0ce8d08b3f5b810e49a8352fdd458606bd5fafe5acdcdc8ff3f57";
    let sample_signature = "1343d7602a4319bd9e82ebb48426054cac6bad34731a8fd897c7d58536fff13f278dfe7a44f4cd3ffa393e49a7c2e93d3652266bb379a532159ba81bab61657e";
    let sample_hashed_message = "40f21d1c30ac1a6739b8bf5c050f72124eb647a916447e7ebb0748726f35bf48";

    let is_valid = verify_signature(hex::decode(sample_pubkey).unwrap().try_into().unwrap(),
        hex::decode(sample_signature).unwrap().try_into().unwrap(),
        hex::decode(sample_hashed_message).unwrap().try_into().unwrap()).unwrap();

    assert!(is_valid);
}

#[test]
fn test_fail_verify_signature() {
    let sample_pubkey = "0350fe40766bc0ce8d08b3f5b810e49a8352fdd458606bd5fafe5acdcdc8ff3f57";
    let sample_signature = "1243d7602a4319bd9e82ebb48426054cac6bad34731a8fd897c7d58536fff13f278dfe7a44f4cd3ffa393e49a7c2e93d3652266bb379a532159ba81bab61657e";
    let sample_hashed_message = "40f21d1c30ac1a6739b8bf5c050f72124eb647a916447e7ebb0748726f35bf48";

    let is_valid = verify_signature(hex::decode(sample_pubkey).unwrap().try_into().unwrap(),
        hex::decode(sample_signature).unwrap().try_into().unwrap(),
        hex::decode(sample_hashed_message).unwrap().try_into().unwrap()).unwrap();

    assert!(!is_valid);
}