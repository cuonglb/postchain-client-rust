use crate::transport::client::{RestClient, RestResponse};
use crate::utils::operation::{Operation, Params, QueryParams};
use crate::utils::transaction::{Transaction, TransactionStatus};
use crate::ft4::types::AuthDescriptor;
use crate::encoding::gtv;

use crate::ft4_log;

#[cfg(test)]
use secp256k1::{Secp256k1, SecretKey, PublicKey};
#[cfg(test)]
use rand::rng;

#[derive(Debug)]
pub enum QueryResult<T> {
    Json(T),
    Bytes(Vec<u8>),
}

/// Represents a keypair with private and public keys
#[derive(Debug)]
pub struct Keypair {
    /// The private key as a 32-byte array
    pub private_key: [u8; 32],
    /// The public key as a 33-byte compressed public key
    pub public_key: [u8; 33],
}

impl Keypair {
    /// Returns a hex dump string of the public key
    pub fn to_string(&self) -> String {
        hex::encode(&self.public_key)
    }
}

/// Generates a new random keypair for testing purposes
/// 
/// # Returns
/// A Keypair containing the private key and corresponding public key
#[cfg(test)]
pub fn generate_keypair() -> Keypair {
    let secp = Secp256k1::new();
    let mut rng = rng();
    let secret_key = SecretKey::new(&mut rng);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize();
    
    Keypair {
        private_key: secret_key.secret_bytes(),
        public_key,
    }
}

pub struct Ft4Client<'a> {
    transport: RestClient<'a>,
    blockchain_rid: String
}

impl<'a> Ft4Client<'a> {
    pub fn new(transport: RestClient<'a>, blockchain_rid: String) -> Self {
        Self { transport, blockchain_rid }
    }

    fn get_account_id(public_key: &[u8; 33]) 
    -> Result<String, crate::utils::hasher::HashError> {
        let gtv_hash = crate::utils::hasher::gtv_hash(Params::ByteArray(public_key.to_vec()), 2)?;
        Ok(hex::encode(gtv_hash))
    }

    async fn process_query<T: serde::de::DeserializeOwned>(
        &self, 
        query: &str, 
        query_args: Option<&'a mut Vec<(&str, Params)>>)
    -> Result<QueryResult<T>, Box<dyn std::error::Error>> {
        let response = self.transport.query(&self.blockchain_rid, None, query, None, query_args).await?;
        match response {
            RestResponse::Json(value) => {
                let result: T = serde_json::from_value(value)?;
                Ok(QueryResult::Json(result))
            },
            RestResponse::Bytes(bytes) => {
                if let Ok(gtv_data) = gtv::decode(&bytes) {
                    //let btree: BTreeMap<String, Params> = gtv_data.into();
                    
                    //let json_value = crate::ft4::utils::gtv_to_json(btree);

                    let json_value = gtv_data.to_json_value();
                    
                    let result: T = serde_json::from_value(json_value)?;
                    Ok(QueryResult::Json(result))
                } else {
                    Ok(QueryResult::Bytes(bytes))
                }
            },
            RestResponse::String(_) => {
                Err("Unexpected string response".into())
            }
        }
    }

    /// Processes a blockchain transaction by signing it with the provided keypairs and sending it to the network.
    /// 
    /// This function handles the complete transaction lifecycle:
    /// 1. Creates a transaction with the provided operations
    /// 2. Signs the transaction with the provided keypairs (single or multi-signature)
    /// 3. Sends the transaction to the blockchain network
    /// 4. Waits for and verifies the transaction status
    /// 
    /// # Arguments
    /// 
    /// * `operations` - A vector of operations to include in the transaction
    /// * `keypairs` - A slice of references to Keypair objects that will be used to sign the transaction
    /// 
    /// # Returns
    /// 
    /// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) if the transaction was successfully processed and confirmed,
    ///                                            or an error if the transaction failed or is still waiting for confirmation
    /// 
    /// # Errors
    /// 
    /// * Returns an error if the transaction is rejected by the network
    /// * Returns an error if the transaction is still waiting for confirmation
    /// * Returns an error if the transaction status is unknown
    /// * Returns an error if there are issues with signing or sending the transaction
    async fn process_transaction(
        &self,
        operations: Vec<Operation<'_>>,
        keypairs: &[&Keypair]
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut tx = Transaction {
            blockchain_rid: hex::decode(&self.blockchain_rid).unwrap(),
            operations: Some(operations),
            ..Default::default()
        };

        if keypairs.len() == 1 {
            tx.sign(&keypairs[0].private_key)?;
        } else {
            let private_keys: Vec<&[u8; 32]> = keypairs.iter().map(|k| &k.private_key).collect();
            tx.multi_sign(&private_keys)?;
        }
        
        self.transport.send_transaction(&tx).await?;
        let rid_hex = tx.tx_rid_hex().unwrap();
        let tx_status = self.transport.get_transaction_status(&self.blockchain_rid, &rid_hex).await?;
        
        ft4_log!(info, "Processing transaction RID {} for public keys {:?}", rid_hex, keypairs.iter().map(|k| k.to_string()).collect::<Vec<_>>());
        match tx_status {
            TransactionStatus::CONFIRMED => {
                ft4_log!(info, "Success!");
                Ok(())
            },
            TransactionStatus::REJECTED => {
                ft4_log!(error, "Failed because TX is rejected");
                Err("Transaction rejected".into())
            },
            TransactionStatus::WAITING => {
                ft4_log!(warn, "Still waiting for transaction status...");
                Err("Transaction waiting".into())
            },
            _ => {
                ft4_log!(error, "Failed because transaction response unknown status.");
                Err("Unknown transaction status".into())
            }
        }
    }

    /// Registers a new account on the blockchain using the FT4 protocol.
    /// 
    /// This function creates a new account with the specified authentication configuration.
    /// It supports both single-signature and multi-signature authentication schemes.
    /// 
    /// # Arguments
    /// 
    /// * `keypairs` - A slice of references to Keypair objects that will be used to sign the transaction
    ///                and authenticate the account. For single-signature accounts, provide a single keypair.
    ///                For multi-signature accounts, provide multiple keypairs.
    /// * `auth_permissions` - Optional vector of permission strings to grant to the account.
    ///                       Defaults to ["A", "T"] which represents Account and Transfer permissions.
    /// * `auth_multisig_required` - Optional number of signatures required for multi-signature accounts.
    ///                             Defaults to 1 for single-signature accounts or the number of keypairs
    ///                             for multi-signature accounts.
    /// 
    /// # Returns
    /// 
    /// * `Result<(), Box<dyn std::error::Error>>` - Ok(()) if the account was successfully registered,
    ///                                            or an error if registration failed.
    /// 
    /// # Examples
    /// 
    /// ```
    /// // Register a single-signature account with default permissions
    /// let keypair = generate_keypair();
    /// ft4_client.register_account(&[&keypair], None, None).await?;
    /// 
    /// // Register a multi-signature account requiring 2 of 3 signatures
    /// let keypair1 = generate_keypair();
    /// let keypair2 = generate_keypair();
    /// let keypair3 = generate_keypair();
    /// ft4_client.register_account(
    ///     &[&keypair1, &keypair2, &keypair3],
    ///     Some(vec!["A", "T", "C"]),
    ///     Some(2)
    /// ).await?;
    /// ```
    pub async fn register_account(&self,
        keypairs: &[&Keypair],
        auth_permissions: Option<Vec<&str>>,
        auth_multisig_required: Option<i64>) -> Result<(), Box<dyn std::error::Error>> {
        let auth_permissions = auth_permissions.unwrap_or(vec!["A", "T"]);
        
        let mut auth_permission_params = Vec::new();

        for auth_permission in auth_permissions.iter() {
            auth_permission_params.push(QueryParams::Text(auth_permission.to_string()));
        }

        // Default is single signature auth_type = 0
        // if multiple keypairs are provided, set auth_type to 1 (multi-signature)
        let mut auth_type = QueryParams::Integer(0);

        if keypairs.len() > 1 {
            auth_type = QueryParams::Integer(1);
        }

        // Expiration rules, must be null ("never expire")
        // for the main auth descriptor ("owner")
        let auth_rules = Params::Null;

        let auth_sigs = keypairs.iter().map(|keypair| {
            Params::ByteArray(keypair.public_key.to_vec())
        }).collect::<Vec<_>>();

        // If multisig, how many signatures are required. Default is 1
        // If single sig, dont include this param

        let auth_multisig_required = auth_multisig_required.unwrap_or(1);

        let auth_body = if auth_sigs.len() == 1 {
            Params::Array(vec![
                Params::Array(auth_permission_params),
                auth_sigs.get(0).unwrap().clone(),
            ]) 
        } else {
            Params::Array(vec![
                Params::Array(auth_permission_params),
                Params::Integer(auth_multisig_required),
                Params::Array(auth_sigs),
            ])
        };

        let auth_descriptors = vec![
                auth_type,
                auth_body,
                auth_rules
            ];

        let ras_open_params = vec![
            Params::Array(auth_descriptors),
            Params::Null
        ];

        let register_account_params = vec![];
        
        let operations = vec![
            Operation::from_list("ft4.ras_open", ras_open_params),
            Operation::from_list("ft4.register_account", register_account_params)
        ];

        self.process_transaction(operations, keypairs).await
    }

    pub async fn get_account_main_auth_descriptor(&self, account_id: &str) -> Result<AuthDescriptor, Box<dyn std::error::Error>> {
        let query = "ft4.get_account_main_auth_descriptor";
        let mut query_args = vec![("account_id", Params::Text(account_id.to_string()))];
        
        self.process_query::<AuthDescriptor>(query, Some(&mut query_args)).await.map(|result| {
            match result {
                QueryResult::Json(auth_descriptor) => auth_descriptor,
                _ => {
                    panic!("Expected JSON response for auth descriptor")
                }
            }
        })
    }

    pub async fn update_main_auth_descriptor(&self) {
        // https://docs.chromia.com/ft4/account-management/multisig
    }

    #[cfg(test)]
    pub async fn setup_test_client() -> Result<Self, Box<dyn std::error::Error>> {
        tracing_subscriber::fmt::init();

        let transport = RestClient {
            node_url: vec!["http://localhost:7740"],
            ..Default::default()
        };

        let blockchain_rid = transport.get_blockchain_rid(0).await.unwrap_or("must_be_run_in_local".to_string());

        if blockchain_rid == "must_be_run_in_local" {
            ft4_log!(error, "This test must be run in local environment");
            return Err("Test must be run in local environment".into());
        }

        Ok(Self { transport, blockchain_rid } )
    }
}

#[tokio::test]
async fn test_ft4_register_account_single_signature() {
    let ft4_client = Ft4Client::setup_test_client().await.unwrap();

    // Test with default auth descriptor (A, T)
    let keypair1 = generate_keypair();
    let result = ft4_client.register_account(&[&keypair1], None, None).await;
    assert_eq!(result.is_ok(), true, "Failed to register account with single signature");

    // Test with custom auth descriptors (A, T, S)
    let keypair2 = generate_keypair();
    let result = ft4_client.register_account(&[&keypair2], Some(vec!["A", "T", "S"]), None).await;
    assert_eq!(result.is_ok(), true, "Failed to register account with single signature");
}

#[tokio::test]
async fn test_ft4_register_account_multi_signatures() {
    let ft4_client = Ft4Client::setup_test_client().await.unwrap();

    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();
    let keypair3 = generate_keypair();

    // Test with multiple keypairs and custom auth descriptors (A, T, S)
    // with multisig required = 3
    let result = ft4_client.register_account(&[&keypair1, &keypair2, &keypair3], Some(vec!["A", "T", "S"]), Some(3)).await;
    assert_eq!(result.is_ok(), true, "Failed to register account with multi signatures");
}

#[test]
fn test_get_account_id_from_public_key() {
    let public_key: [u8; 33] = hex::decode("022672944E1D542487601145FF42B2953F32CC7DA1167EBD3D0087954816EDD146").unwrap().try_into().unwrap();
    let account_id = Ft4Client::get_account_id(&public_key).unwrap();
    assert_eq!(account_id, "885a6648772ab9615ccd88d25201402f734b43ef20da959623591b0dca5098c5");
}

#[tokio::test]
async fn test_ft4_get_account_main_auth_descriptor() {
    let ft4_client = Ft4Client::setup_test_client().await.unwrap();
    let keypair = generate_keypair();
    let account_id = Ft4Client::get_account_id(&keypair.public_key).unwrap();

    let result = ft4_client.register_account(&[&keypair], None, None).await;
    assert_eq!(result.is_ok(), true, "Failed to register account with single signature");

    let result = ft4_client.get_account_main_auth_descriptor(&account_id).await;
    assert!(result.is_ok(), "Failed to get account main auth descriptor");
    
    let auth_descriptor = result.unwrap();
    assert_eq!(auth_descriptor.account_id, account_id.to_uppercase());
}