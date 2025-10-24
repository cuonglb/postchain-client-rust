//! Client module for interacting with Postchain blockchain nodes via REST API.
//! 
//! This module provides functionality for:
//! - Querying blockchain nodes
//! - Managing transactions
//! - Handling REST API communication
//! - Error handling

extern crate serde_json;
extern crate url;

use reqwest::{header::CONTENT_TYPE, Client};
use url::Url;

use serde_json::Value;
use std::{error::Error, time::Duration};

use crate::utils::transaction::{Transaction, TransactionConfirmationProofData, TransactionStatus};

/// A REST client for interacting with Postchain blockchain nodes.
/// 
/// This client handles communication with blockchain nodes, including:
/// - Transaction submission and status checking
/// - Node discovery and management
/// - Query execution
/// - Error handling
#[derive(Debug)]
pub struct RestClient<'a> {
    /// List of node URLs to connect to
    pub node_url: Vec<&'a str>,
    /// Request timeout in seconds
    pub request_time_out: u64,
    /// Number of attempts to poll for transaction status
    pub poll_attemps: u64,
    /// Interval between poll attempts in seconds
    pub poll_attemp_interval_time: u64
}

/// Response types that can be returned from REST API calls.
#[derive(Debug)]
pub enum RestResponse {
    /// Plain text response
    String(String),
    /// JSON response
    Json(Value),
    /// Binary response
    Bytes(Vec<u8>),
}

/// HTTP methods supported by the REST client.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum RestRequestMethod {
    /// HTTP GET method
    GET,
    /// HTTP POST method
    POST,
}

impl<'a> Default for RestClient<'a> {
    fn default() -> Self {
        RestClient {
            node_url: vec!["http://localhost:7740"],
            request_time_out: 30,
            poll_attemps: 5,
            poll_attemp_interval_time: 5
        }
    }
}

/// Types of errors that can occur during REST operations
#[derive(Debug)]
pub enum TypeError {
    /// Error from the reqwest client
    FromReqClient,
    /// Error from the REST API
    FromRestApi,
}

/// Error type for REST operations
#[derive(Debug)]
pub struct RestError {
    /// HTTP status code if available
    pub status_code: Option<String>,
    /// Error message if available
    pub error_str: Option<String>,
    /// JSON error response if available
    pub error_json: Option<Value>,
    /// Type of error that occurred
    pub type_error: TypeError,
}

impl Error for RestError {}

impl Default for RestError {
    fn default() -> Self {
        RestError {
            status_code: None,
            error_str: None,
            error_json: None,
            type_error: TypeError::FromRestApi,
        }
    }
}

impl std::fmt::Display for RestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut hsc = "N/A".to_string();
        let mut err_str = "N/A".to_string();

        if let Some(val) = &self.status_code {
            hsc = val.clone();
        }

        if let Some(val) = &self.error_str {
            err_str = val.clone();
        }

        write!(f, "{:?} {} {}", self.type_error, hsc, err_str)
    }
}

impl<'a> RestClient<'a> {
    /// Retrieves a list of node URLs from the blockchain directory.
    ///
    /// # Arguments
    /// * `brid` - Blockchain RID (Resource Identifier)
    ///
    /// # Returns
    /// * `Result<Vec<String>, RestError>` - List of node URLs on success, or error on failure
    ///
    /// # Example
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RestClient::default();
    /// let nodes = client.get_nodes_from_directory("blockchain_rid").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_nodes_from_directory(&self, brid: &str) -> Result<Vec<String>, RestError> {
        let directory_brid = self.get_blockchain_rid(0).await?;

        let path_segments = &["query", &directory_brid];
        let query_params = vec![
            ("type", "cm_get_blockchain_api_urls"),
            ("blockchain_rid", brid),
        ];
        let query_body_json = None;
        let query_body_raw = None;

        let resp = self
            .postchain_rest_api(
                RestRequestMethod::GET,
                Some(path_segments),
                Some(&query_params),
                query_body_json,
                query_body_raw
            )
            .await;

        match resp {
            Ok(RestResponse::Json(json_val)) => {
                let list_of_nodes = json_val
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|value| value.as_str().map(String::from))
                    .collect();
                Ok(list_of_nodes)
            }
            Ok(RestResponse::String(str_val)) => Ok(vec![str_val]),
            Ok(_) => Ok(vec!["nop".to_string()]),
            Err(error) => {
                tracing::error!("Can't get API urls from DC chain: {} because of error: {:?}", brid, error);
                Err(error)
            }
        }
    }

    /// Retrieves the blockchain RID for a given blockchain IID.
    ///
    /// # Arguments
    /// * `blockchain_iid` - Blockchain Instance Identifier
    ///
    /// # Returns
    /// * `Result<String, RestError>` - Blockchain RID on success, or error on failure
    pub async fn get_blockchain_rid(&self, blockchain_iid: u8) -> Result<String, RestError> {
        let resp: Result<RestResponse, RestError> = self
            .postchain_rest_api(
                RestRequestMethod::GET,
                Some(&[&format!("/brid/iid_{blockchain_iid}")]),
                None,
                None,
                None
            )
            .await;

        if let Err(error) = resp {
            tracing::error!("Can't get blockchain RID with IID = {} because of error: {:?}", blockchain_iid, error);
            return Err(error);
        }

        let resp_val: RestResponse = resp.unwrap();

        match resp_val {
            RestResponse::String(val) => Ok(val.to_string()),
            _ => Ok("".to_string()),
        }
    }

    /// Prints error information and determines if the error should be ignored.
    ///
    /// # Arguments
    /// * `error` - The REST error to print
    /// * `ignore_all_errors` - Whether to ignore all errors
    ///
    /// # Returns
    /// * `bool` - Whether the error should stop execution
    pub fn print_error(&self, error: &RestError, ignore_all_errors: bool) -> bool {
        println!(">> Error(s)");

        if let Some(error_str) = &error.error_str {
            println!("{error_str}");
        } else {
            let val = &error.error_json.as_ref().unwrap();
            let pprint = serde_json::to_string_pretty(val).unwrap();
            println!("{pprint}");
        }

        if ignore_all_errors {
            println!("Allow ignore this error");
            return false
        }

        true
    }

    /// Detects the Merkle hash version used by a blockchain.
    ///
    /// This function queries the blockchain's configuration to determine which version
    /// of the Merkle hash algorithm is being used. If the query fails or the version
    /// information is not available, it defaults to version 1.
    ///
    /// # Arguments
    /// * `brid` - The blockchain RID (Resource Identifier) as a hex-encoded string
    ///
    /// # Returns
    /// * `u8` - The Merkle hash version number (defaults to 1 if not specified)
    ///
    /// # Example
    /// ```no_run
    /// # use postchain_client::transport::RestClient;
    /// # async fn example() {
    /// let client = RestClient::default();
    /// let brid = "DCE5D72ED7E1675291AFE7F9D649D898C8D3E7411E52882D03D1B3D240BDD91B";
    /// let hash_version = client.detect_merkle_hash_version(brid).await;
    /// println!("Blockchain uses Merkle hash version {}", hash_version);
    /// # }
    /// ```
    pub async fn detect_merkle_hash_version(&self, brid: &str) -> u8 {
        tracing::info!("Detecting merkle hash version of blockchain: {}", brid); 

        let mut merkle_hash_version = 1;

        if let Ok(RestResponse::Json(json_val)) = self.postchain_rest_api(
            RestRequestMethod::GET,
            Some(&["config", brid, "features"]),
            None,
            None,
            None
        ).await {
            if let Some(version) = json_val["merkle_hash_version"].as_u64() {
                merkle_hash_version = version as u8;
                tracing::info!("Found merkle hash version = {}", merkle_hash_version);
                return merkle_hash_version;
            }
        }

        tracing::warn!("Failed to detect merkle hash version, using default version = {}", merkle_hash_version);
        merkle_hash_version
    }

    /// Updates the list of node URLs used by the client.
    ///
    /// # Arguments
    /// * `node_urls` - New list of node URLs to use
    pub fn update_node_urls(&mut self, node_urls: &'a [String]) {
        self.node_url = node_urls.iter().map(String::as_str).collect();
    }

    // Transaction status
    // GET /tx/{blockchain_rid}/{transaction_rid}/status
    /// Gets the status of a transaction without polling.
    ///
    /// # Arguments
    /// * `blockchain_rid` - Blockchain RID
    /// * `tx_rid` - Transaction RID
    ///
    /// # Returns
    /// * `Result<TransactionStatus, RestError>` - Transaction status or error
    pub async fn get_transaction_status(&self, blockchain_rid: &str, tx_rid: &str) -> Result<TransactionStatus, RestError> {
        self.get_transaction_status_with_poll(blockchain_rid, tx_rid, 0).await
    }

    /// Fetches and parses transaction-related data from a Postchain node.
    ///
    /// This is a generic helper function to retrieve data associated with a transaction
    /// (such as confirmation proofs or raw transaction data) from a Postchain node's
    /// REST API. It encapsulates the common logic of constructing the REST API call,
    /// making the request, extracting a specific string field from the JSON response,
    /// and then parsing that string using a provided parsing function.
    ///
    /// # Type Parameters
    ///
    /// * `R`: The expected return type after parsing the extracted string (e.g., `Transaction` or `TransactionConfirmationProofData`).
    /// * `F`: A closure type that takes a string slice (`&str`) and returns a `Result<R, String>`.
    ///   This closure encapsulates the specific parsing logic (e.g., `Transaction::from_raw_data` or `Transaction::confirmation_proof`).
    ///
    /// # Arguments
    ///
    /// * `blockchain_rid` - A string slice representing the Blockchain RID.
    /// * `tx_rid` - An optional string slice representing the Transaction RID. If `None`, an empty string is used in the path.
    /// * `endpoint_suffix` - An optional string slice that will be appended to the base
    ///   transaction path (`/tx/{blockchain_rid}/{tx_rid}`). For example, use `"confirmationProof"`
    ///   to get the confirmation proof, or `None` to get the raw transaction data if the base path
    ///   itself yields the desired content.
    /// * `field_name` - The name of the JSON field to extract the data from (e.g., `"proof"` or `"tx"`).
    ///   If `None`, the entire JSON response is converted to a string and passed to `parser_fn`.
    /// * `parser_fn` - A closure or function pointer that takes the extracted string slice
    ///   (or the stringified JSON response if `field_name` is `None`)
    ///   and attempts to parse it into the desired return type `R`.
    /// * `prefix_query` - The base path prefix for the API call (e.g., `"tx"` for `/tx/{rid}`).
    /// * `query_params` - An optional vector of key-value tuple string slices `(&str, &str)`
    ///   representing query parameters to append to the URL (e.g., `vec![("param", "value")]`).
    ///
    /// # Returns
    ///
    /// A `Result<R, RestError>`:
    /// - `Ok(R)`: On successful retrieval and parsing of the data.
    /// - `Err(RestError)`: If the request fails, the response is not JSON, the specified
    ///   `field_name` is missing or invalid, or the `parser_fn` returns an error.
    ///
    /// # Errors
    ///
    /// This function can return a `RestError` in the following cases:
    /// - If the underlying `postchain_rest_api` call fails (e.g., network issues, HTTP errors).
    /// - If the response from the node is not a JSON object.
    /// - If `field_name` is `Some` and the JSON response does not contain the specified field,
    ///   or if its value is not a string.
    /// - If the `parser_fn` fails to parse the extracted string (its `Err(String)` is wrapped into a `RestError`).
    ///
    /// # Example (Conceptual Usage within other methods)
    ///
    /// ```rust
    /// # use postchain_client::transport::{RestClient, RestError, RestRequestMethod, RestResponse};
    /// # use serde_json::Value;
    /// # // Mock implementations for example to compile
    /// # #[derive(Debug)]
    /// # struct Transaction;
    /// # impl Transaction {
    /// #    fn confirmation_proof(_s: &str) -> Result<Self, String> { Ok(Transaction) }
    /// #    fn from_raw_data(_s: &str) -> Result<Self, String> { Ok(Transaction) }
    /// # }
    /// # #[derive(Debug)]
    /// # struct TransactionConfirmationProofData;
    /// # impl RestClient<'_> {
    /// #    async fn postchain_rest_api(&self, _method: RestRequestMethod, _path_segments: Option<&[&str]>,
    /// #                                 _query_params: Option<&Vec<(&str, &str)>>, _body: Option<&str>, _headers: Option<&[(&str, &str)]>) -> Result<RestResponse, RestError> {
    /// #        Ok(RestResponse::Json(Value::String("mock_data".to_string())))
    /// #    }
    /// # }
    ///
    /// # async fn _example_usage(client: &RestClient<'_>, blockchain_rid: &str, tx_rid: &str) -> Result<(), RestError> {
    /// // How `get_confirmation_proof` might use this generic function:
    /// let proof_data: TransactionConfirmationProofData = client.get_transaction_data(
    ///     blockchain_rid,
    ///     Some(tx_rid), // Tx RID is often required for proof
    ///     Some("confirmationProof"),
    ///     Some("proof"), // Extract the "proof" field
    ///     |s| Transaction::confirmation_proof(s),
    ///     "tx", // Prefix for transaction related endpoints
    ///     None, // No additional query parameters
    /// ).await?;
    /// println!("Proof data: {:?}", proof_data);
    ///
    /// // How `get_raw_transaction_data` might use this generic function:
    /// let raw_tx_data: Transaction = client.get_transaction_data(
    ///     blockchain_rid,
    ///     Some(tx_rid),
    ///     None, // No endpoint suffix for raw transaction data
    ///     Some("tx"), // Extract the "tx" field
    ///     |s| Transaction::from_raw_data(s),
    ///     "tx",
    ///     None,
    /// ).await?;
    /// println!("Raw TX data: {:?}", raw_tx_data);
    ///
    /// // Example with query parameters and parsing the whole response if no specific field needed
    /// // (Hypothetical: if a specific endpoint returns a simple string that needs parsing)
    /// let some_parsed_value: String = client.get_transaction_data(
    ///     blockchain_rid,
    ///     None, // No tx_rid needed for this hypothetical call
    ///     Some("some_simple_value_endpoint"),
    ///     None, // No specific field name, parse the whole response string
    ///     |s| Ok(s.to_string()), // Simple parser that returns the string itself
    ///     "data", // Different prefix for this type of data
    ///     Some(&vec![("version", "1")]), // Example query parameter
    /// ).await?;
    /// println!("Some parsed value: {}", some_parsed_value);
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    // Yes, it has too many arguments and needs to be optimized :)
    async fn get_transaction_data<R, F>(&self, blockchain_rid: &str, tx_rid: Option<&str>, endpoint_suffix: Option<&str>,
        field_name: Option<&str>, parser_fn: F , prefix_query: &str, query_params: Option<&Vec<(&str, &str)>>) -> Result<R, RestError>
    where
        F: FnOnce(&str) -> Result<R, String>,
    {
        let mut path_segments = vec![prefix_query, blockchain_rid, tx_rid.unwrap_or("")];
        if let Some(suffix) = endpoint_suffix {
            path_segments.push(suffix);
        }

        let resp = self
            .postchain_rest_api(
                RestRequestMethod::GET,
                Some(path_segments.as_slice()),
                query_params,
                None,
                None,
            )
            .await?;

        match resp {
            RestResponse::Json(json_val) => {
                match field_name {
                    Some(field) => {
                        match json_val.get(field).and_then(|v| v.as_str()) {
                            Some(data_str) => {
                                parser_fn(data_str).map_err(|e| RestError {
                                    error_str: Some(format!(
                                        "Failed to parse '{field}' field: {e}"
                                    )),
                                    ..RestError::default()
                                })
                            }
                            None => Err(RestError {
                                error_str: Some(format!(
                                    "Missing or invalid '{field}' field in response"
                                )),
                                ..RestError::default()
                            }),
                        }
                    },
                    None => {
                        // When no field is specified, parse the entire JSON value as a string
                        parser_fn(json_val.to_string().as_str()).map_err(|e| RestError {
                            error_str: Some(format!("Failed to parse response: {e}")),
                            ..RestError::default()
                        })
                    }
                }
            }
            _ => Err(RestError {
                error_str: Some("Expected JSON response".to_string()),
                ..RestError::default()
            }),
        }
    }

    /// Retrieves the confirmation proof for a given transaction.
    ///
    /// This function makes a GET request to the `/tx/{blockchain_rid}/{tx_rid}/confirmationProof`
    /// endpoint of the Postchain node to fetch the cryptographic proof that a transaction
    /// has been confirmed on the blockchain.
    ///
    /// # Arguments
    /// * `blockchain_rid` - A string slice representing the Blockchain RID (Resource Identifier)
    /// * `tx_rid` - A string slice representing the Transaction RID (Resource Identifier)
    ///
    /// # Returns
    /// * `Result<TransactionConfirmationProofData, RestError>` - Returns `Ok(TransactionConfirmationProofData)`
    ///   on successful retrieval and parsing of the proof, or `Err(RestError)` if the request fails,
    ///   the response is not JSON, or the 'proof' field is missing/invalid.
    ///
    /// # Errors
    /// This function can return a `RestError` in the following cases:
    /// - If the underlying `postchain_rest_api` call fails (e.g., network issues, node unreachable).
    /// - If the response from the node is not a JSON object.
    /// - If the JSON response does not contain a "proof" field, or if the "proof" field is not a string.
    /// - If the string value of the "proof" field cannot be successfully parsed into a `TransactionConfirmationProofData` struct.
    ///
    /// # Example
    /// ```no_run
    /// # use postchain_client::transport::RestClient;
    /// # use postchain_client::utils::transaction::TransactionConfirmationProofData;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RestClient::default();
    /// let blockchain_rid = "your_blockchain_rid_hex_string"; // Replace with actual blockchain RID
    /// let tx_rid = "your_transaction_rid_hex_string";     // Replace with actual transaction RID
    ///
    /// match client.get_confirmation_proof(blockchain_rid, tx_rid).await {
    ///     Ok(proof_data) => {
    ///         println!("Successfully retrieved confirmation proof:");
    ///         println!("Block height: {}", proof_data.block_height);
    ///         // Further processing of proof_data...
    ///     },
    ///     Err(e) => {
    ///         eprintln!("Failed to get confirmation proof: {}", e);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_confirmation_proof(&self, blockchain_rid: &str, tx_rid: &str) -> Result<TransactionConfirmationProofData, RestError> {
        self.get_transaction_data(
            blockchain_rid,
            Some(tx_rid),
            Some("confirmationProof"),
            Some("proof"),
            Transaction::confirmation_proof,
            "tx",
            None
        ).await
    }

    /// Retrieves the raw transaction data for a given transaction.
    ///
    /// This function makes a GET request to the `/tx/{blockchain_rid}/{tx_rid}` endpoint
    /// of the Postchain node to fetch the raw hexadecimal representation of a transaction.
    ///
    /// # Arguments
    /// * `blockchain_rid` - A string slice representing the Blockchain RID.
    /// * `tx_rid` - A string slice representing the Transaction RID.
    ///
    /// # Returns
    /// * `Result<Transaction, RestError>` - Returns `Ok(Transaction)` on successful retrieval
    ///   and parsing of the raw transaction data, or `Err(RestError)` if the request fails,
    ///   the response is not JSON, or the 'tx' field is missing/invalid.
    ///
    /// # Errors
    /// This function can return a `RestError` in the following cases:
    /// - If the underlying `postchain_rest_api` call fails (e.g., network issues, node unreachable).
    /// - If the response from the node is not a JSON object.
    /// - If the JSON response does not contain a "tx" field, or if the "tx" field is not a string.
    /// - If the string value of the "tx" field cannot be successfully parsed into a `Transaction` struct
    ///   by `Transaction::from_raw_data`.
    ///
    /// # Example
    /// ```no_run
    /// # use postchain_client::transport::RestClient;
    /// # use postchain_client::utils::transaction::Transaction;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = RestClient::default();
    /// let blockchain_rid = "your_blockchain_rid_hex_string"; // Replace with actual blockchain RID
    /// let tx_rid = "your_transaction_rid_hex_string";     // Replace with actual transaction RID
    ///
    /// match client.get_raw_transaction_data(blockchain_rid, tx_rid).await {
    ///     Ok(transaction) => {
    ///         println!("Successfully retrieved raw transaction data: {:?}", transaction);
    ///         // Further processing of transaction object...
    ///     },
    ///     Err(e) => {
    ///         eprintln!("Failed to get raw transaction data: {}", e);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_raw_transaction_data(&self, blockchain_rid: &str, tx_rid: &str) -> Result<Transaction, RestError>{
        self.get_transaction_data(blockchain_rid, Some(tx_rid), None, Some("tx"), |s| {
            Transaction::from_raw_data(s)
        }, "tx", None).await
    }

    /// Fetches and deserializes transaction information from the Postchain node.
    ///
    /// This function acts as a wrapper around `get_transaction_data` to retrieve and
    /// deserialize generic transaction-related data. It expects the Postchain API
    /// to return a JSON structure that can be directly deserialized into the specified
    /// type `T`.
    ///
    /// The API endpoint used is typically `/transactions/{blockchain_rid}[/{tx_rid}]`.
    ///
    /// # Type Parameters
    ///
    /// * `T`: The target type to deserialize the JSON response into. This type must
    ///   implement `serde::Deserialize` to enable automatic deserialization.
    ///
    /// # Arguments
    ///
    /// * `blockchain_rid` - A string slice representing the Blockchain RID.
    /// * `tx_rid` - An optional string slice representing a specific Transaction RID.
    ///   If provided, the request targets a single transaction's info. If `None`,
    ///   the request might retrieve a list of transactions or general transaction-related data
    ///   depending on the `query_params`.
    /// * `query_params` - An optional vector of key-value tuple string slices `(&str, &str)`
    ///   representing additional query parameters for the API call (e.g., pagination, filtering).
    ///
    /// # Returns
    ///
    /// A `Result<T, RestError>`:
    /// - `Ok(T)`: On successful retrieval and deserialization of the data.
    /// - `Err(RestError)`: If the request fails, the response is not valid JSON for `T`,
    ///   or any underlying `get_transaction_data` error occurs.
    ///
    /// # Errors
    ///
    /// This function can return a `RestError` in the following cases:
    /// - If the underlying HTTP request fails (e.g., network issues, invalid URL).
    /// - If the Postchain node returns a non-JSON response.
    /// - If the JSON response cannot be deserialized into the target type `T` (e.g.,
    ///   missing fields, type mismatches).
    ///
    /// # Example
    ///
    /// ```rust
    /// # async fn _example_usage() -> Result<(), RestError> {
    /// let client = MockRestClient;
    /// let blockchain_rid = "mock_blockchain_rid";
    ///
    /// // Fetch info for a specific transaction
    /// let tx_id = "tx_id_123";
    /// let single_tx_info: TransactionInfo = client.get_transactions_info(
    ///     blockchain_rid,
    ///     Some(tx_id),
    ///     None,
    /// ).await?;
    /// println!("Single transaction info: {:?}", single_tx_info);
    /// assert_eq!(single_tx_info.id, "tx_id_123");
    ///
    /// // Fetch a list of transactions (assuming the API supports this with tx_rid = None)
    /// let all_tx_info: TransactionsList = client.get_transactions_info(
    ///     blockchain_rid,
    ///     None,
    ///     Some(&vec![("limit", "10")]),
    /// ).await?;
    /// println!("All transactions info: {:?}", all_tx_info);
    /// assert_eq!(all_tx_info.transactions.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_transactions_info<T>(&self, blockchain_rid: &str, tx_rid: Option<&str>, query_params: Option<&Vec<(&str, &str)>>) -> Result<T, RestError> 
    where
        T: for<'de> serde::Deserialize<'de>
    {
        self.get_transaction_data(blockchain_rid, tx_rid, None, None, |s| {
            match serde_json::from_str::<T>(s) {
                Ok(r) => Ok(r),
                Err(e) => Err(format!("Failed to fetch transaction info: {e}"))
            }
        }, "transactions", query_params).await
    }

    /// Fetches the total number of successful transactions for a given blockchain.
    ///
    /// This function retrieves the count of successful transactions by calling the
    /// `/transactions/{blockchain_rid}/count` endpoint of the Postchain node.
    /// It specifically parses the `transactionsCount` field from the JSON response.
    ///
    /// # Arguments
    ///
    /// * `blockchain_rid` - A string slice representing the Blockchain RID for which
    ///   to retrieve the transaction count.
    ///
    /// # Returns
    ///
    /// A `Result<i64, RestError>`:
    /// - `Ok(i64)`: On successful retrieval and parsing of the transaction count.
    /// - `Err(RestError)`: If the request fails, the response is not valid JSON,
    ///   the `transactionsCount` field is missing or not a valid `i64`, or any
    ///   underlying `get_transaction_data` error occurs.
    ///
    /// # Errors
    ///
    /// This function can return a `RestError` in the following cases:
    /// - If the underlying HTTP request fails (e.g., network issues, invalid URL).
    /// - If the Postchain node returns a non-JSON response.
    /// - If the JSON response does not contain the `transactionsCount` field, or
    ///   if its value cannot be interpreted as an integer.
    ///
    /// # Example
    ///
    /// ```rust
    /// # async fn _example_usage() -> Result<(), RestError> {
    /// let client = MockRestClient;
    /// let blockchain_rid = "mock_blockchain_rid";
    ///
    /// let count = client.get_number_successful_transactions(blockchain_rid).await?;
    /// println!("Number of successful transactions: {}", count);
    /// assert_eq!(count, 42);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_number_successful_transactions(&self, blockchain_rid: &str) -> Result<i64, RestError>{
        self.get_transaction_data(blockchain_rid, Some("count"), None, None, |s| {
            let transactions_count = serde_json::from_str::<serde_json::Value>(s)
            .ok().and_then(|v| v["transactionsCount"].as_i64()).unwrap();
            Ok(transactions_count)
        }, "transactions", None).await
    }

    /// Gets the status of a transaction with polling for confirmation.
    ///
    /// # Arguments
    /// * `blockchain_rid` - Blockchain RID
    /// * `tx_rid` - Transaction RID
    /// * `attempts` - Number of polling attempts made so far
    ///
    /// # Returns
    /// * `Result<TransactionStatus, RestError>` - Transaction status or error
    pub async fn get_transaction_status_with_poll(&self, blockchain_rid: &str, tx_rid: &str, attempts: u64) -> Result<TransactionStatus, RestError> {
        tracing::info!("Waiting for transaction status of blockchain RID: {} with tx: {} | attempt: {}", blockchain_rid, tx_rid, attempts);

        if attempts >= self.poll_attemps {
            tracing::warn!("Transaction status still in waiting status after {} attempts", attempts);
            return Ok(TransactionStatus::WAITING);
        }

        let resp = self.postchain_rest_api(RestRequestMethod::GET,
            Some(&["tx", blockchain_rid, tx_rid, "status"]),
            None,
            None,
            None).await?;
        match resp {
            RestResponse::Json(val) => {
                let status: serde_json::Map<String, Value> = serde_json::from_value(val).unwrap();
                if let Some(status_value) = status.get("status") {
                    let status_value = status_value.as_str();
                    match status_value {
                        Some("waiting") => {
                            // Waiting for transaction rejected or confirmed!!!
                            // Interval time = 5 secs on each attempt
                            // Break after 5 attempts
                            tokio::time::sleep(Duration::from_secs(self.poll_attemp_interval_time)).await;
                            return Box::pin(self.get_transaction_status_with_poll(blockchain_rid, tx_rid, attempts + 1)).await;
                        },
                        Some("confirmed") => {
                            tracing::info!("Transaction confirmed!");
                            return Ok(TransactionStatus::CONFIRMED)
                        },
                        Some("rejected") => {
                            tracing::warn!("Transaction rejected!");
                            return Ok(TransactionStatus::REJECTED)
                        },
                        _ => return Ok(TransactionStatus::UNKNOWN)
                    };
                }
                Ok(TransactionStatus::UNKNOWN)
            }
            _ => {
                Ok(TransactionStatus::UNKNOWN)
            }
        }
    }

    // Submit transaction
    // POST /tx/{blockchainRid}
    /// Sends a transaction to the blockchain.
    ///
    /// # Arguments
    /// * `tx` - Transaction to send
    ///
    /// # Returns
    /// * `Result<RestResponse, RestError>` - Response from the blockchain or error
    pub async fn send_transaction(&self, tx: &Transaction) -> Result<RestResponse, RestError> {
        let txe = tx.gvt_hex_encoded();

        let resq_body: serde_json::Map<String, Value> =
            vec![("tx".to_string(), serde_json::json!(txe))]
                .into_iter()
                .collect();

        let blockchain_rid = hex::encode(tx.blockchain_rid.clone()).as_str().to_owned();

        tracing::info!("Sending transaction to {}", blockchain_rid); 

        self
            .postchain_rest_api(
                RestRequestMethod::POST,
                Some(&["tx", &blockchain_rid]),
                None,
                Some(serde_json::json!(resq_body)),
                None
            )
            .await
    }

    // Make a query with GTV encoded response
    // POST /query_gtv/{blockchainRid}
    /// Executes a query on the blockchain.
    ///
    /// # Arguments
    /// * `brid` - Blockchain RID
    /// * `query_prefix` - Optional prefix for the query endpoint
    /// * `query_type` - Type of query to execute
    /// * `query_params` - Optional query parameters
    /// * `query_args` - Optional query arguments
    ///
    /// # Returns
    /// * `Result<RestResponse, RestError>` - Query response or error
    pub async fn query(
        &self,
        brid: &str,
        query_prefix: Option<&str>,
        query_type: &'a str,
        query_params: Option<&'a mut Vec<(&'a str, &'a str)>>,
        query_args: Option<&'a mut Vec<(String, crate::utils::operation::Params)>>,
    ) -> Result<RestResponse, RestError> {
        let query_prefix_str = query_prefix.unwrap_or("query_gtv");

        let mut query_args_converted: Option<Vec<(&str, crate::utils::operation::Params)>> = query_args.map(|args| {
            args.iter()
                .map(|(key, params)| (key.as_ref(), params.clone()))
                .collect()
        });

        let encode_str = crate::encoding::gtv::encode(query_type, query_args_converted.as_mut());      
        
        tracing::info!("Querying {} to {}", query_type, brid); 

        self.postchain_rest_api(
            RestRequestMethod::POST,
            Some(&[query_prefix_str, brid]),
            query_params.as_deref(),
            None,
            Some(encode_str)
        ).await
    }

    /// Makes a REST API request to a Postchain node.
    ///
    /// # Arguments
    /// * `method` - HTTP method to use
    /// * `path_segments` - URL path segments
    /// * `query_params` - Query parameters
    /// * `query_body_json` - JSON request body
    /// * `query_body_raw` - Raw request body
    ///
    /// # Returns
    /// * `Result<RestResponse, RestError>` - API response or error
    async fn postchain_rest_api(
        &self,
        method: RestRequestMethod,
        path_segments: Option<&[&str]>,
        query_params: Option<&'a Vec<(&'a str, &'a str)>>,
        query_body_json: Option<Value>,
        query_body_raw: Option<Vec<u8>>
    ) -> Result<RestResponse, RestError> {
        let mut node_index: usize = 0;
        loop {
            let result = self.postchain_rest_api_with_poll(method,
                path_segments, query_params,
                query_body_json.clone(), query_body_raw.clone(), node_index).await;

            if let Err(ref error) = result {
                node_index += 1;

                if node_index >= self.node_url.len() || error.status_code.is_some() {
                    return result;
                }
                tracing::info!("The API endpoint can't be reached; will try another one!");
                continue;
            }
            return result;
        }
    }

    /// Makes a REST API request with retry logic for failed nodes.
    ///
    /// # Arguments
    /// * `method` - HTTP method to use
    /// * `path_segments` - URL path segments
    /// * `query_params` - Query parameters
    /// * `query_body_json` - JSON request body
    /// * `query_body_raw` - Raw request body
    /// * `node_index` - Index of the node to try
    ///
    /// # Returns
    /// * `Result<RestResponse, RestError>` - API response or error
    async fn postchain_rest_api_with_poll(
        &self,
        method: RestRequestMethod,
        path_segments: Option<&[&str]>,
        query_params: Option<&'a Vec<(&'a str, &'a str)>>,
        query_body_json: Option<Value>,
        query_body_raw: Option<Vec<u8>>,
        node_index: usize,
    ) -> Result<RestResponse, RestError> {

        let mut url = Url::parse(self.node_url[node_index]).unwrap();

        tracing::info!("Requesting on API endpoint: {}", url);

        if let Some(ps) = path_segments {
            if !ps.is_empty() {
                let psj = ps.join("/");
                url.set_path(&psj);
            }
        }

        if let Some(qp) = query_params {
            if !qp.is_empty() {
                for (name, value) in qp {
                    url.query_pairs_mut().append_pair(name, value);
                }
            }
        }

        if method == RestRequestMethod::POST
            && query_body_json.is_none()
            && query_body_raw.is_none()
        {
            let error_str = "Error: POST request need a body [json or binary].".to_string();

            tracing::error!(error_str);

            return Err(RestError {
                type_error: TypeError::FromRestApi,
                error_str: Some(error_str),
                status_code: None,
                ..Default::default()
            });
        }

        let rest_client = Client::new();

        let req_result = match method {
            RestRequestMethod::GET => {
                rest_client
                    .get(url.clone())
                    .timeout(Duration::from_secs(self.request_time_out))
                    .send()
                    .await
            }

            RestRequestMethod::POST => {
                if let Some(qb) = query_body_json {
                    rest_client
                        .post(url.clone())
                        .timeout(Duration::from_secs(self.request_time_out))
                        .json(&qb)
                        .send()
                        .await
                } else {
                    let r_body = reqwest::Body::from(query_body_raw.unwrap());
                    rest_client
                        .post(url.clone())
                        .timeout(Duration::from_secs(self.request_time_out))
                        .body(r_body)
                        .send()
                        .await
                }
            }
        };

        let req_result_match = match req_result {
            Ok(resp) => {
                let http_status_code = resp.status().to_string();
                let http_resp_header = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
                let json_resp = http_resp_header.contains("application/json");
                let octet_stream_resp = http_resp_header.contains("application/octet-stream");

                if http_status_code.starts_with('4') || http_status_code.starts_with('5') {
                    let mut err = RestError {
                        status_code: Some(http_status_code),
                        type_error: TypeError::FromRestApi,
                        ..Default::default()
                    };

                    if json_resp {
                        let error_json = resp.json().await.unwrap();
                        err.error_json = Some(error_json);
                    } else {
                        let error_str = resp.text().await.unwrap();
                        err.error_str = Some(error_str);
                    }

                    tracing::error!("{:?}", err);

                    return Err(err);
                }

                let rest_resp: RestResponse;

                if json_resp {
                    let val = resp.json().await.unwrap();
                    rest_resp = RestResponse::Json(val);
                } else if octet_stream_resp {
                    let bytes = resp.bytes().await.unwrap();
                    rest_resp = RestResponse::Bytes(bytes.to_vec());
                } else {
                    let val = resp.text().await.unwrap();
                    rest_resp = RestResponse::String(val);
                }

                Ok(rest_resp)
            }
            Err(error) => {
                let rest_error = RestError {
                    error_str: Some(error.to_string()),
                    type_error: TypeError::FromReqClient,
                    ..Default::default()};

                tracing::error!("{:?}", rest_error);

                Err(rest_error)
            },
        };

        req_result_match
    }
}

#[tokio::test]
async fn client_detect_merkle_hash_version() {
    let rc = RestClient{
        node_url: vec!["https://node11.devnet1.chromia.dev:7740"],
        ..Default::default()
    };

    let blockchain_rid = "DCE5D72ED7E1675291AFE7F9D649D898C8D3E7411E52882D03D1B3D240BDD91B";

    let merkle_hash_version = rc.detect_merkle_hash_version(blockchain_rid).await;

    assert_eq!(merkle_hash_version, 2);
}