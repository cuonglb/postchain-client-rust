use postchain_client::{
    utils::{operation::{Params, Operation}, transaction::Transaction},
    transport::client::{RestResponse, RestClient, RestError},
    encoding::gtv
};

async fn do_query_gtv_using_params(rc: &RestClient<'_>, brid: &str) {
    // Query GTV with no arguments
    if let Ok(result) = rc.query::<&str>(brid, None, "api_version", None, None).await {
        if let RestResponse::Bytes(val) = result {
            let api_version: i64 = gtv::decode(&val).unwrap().into();
            println!("api version = {:?}", api_version);
        }
    }

    // Query GTV with params
    let mut args = vec![
        ("include_inactive", Params::Boolean(true))
        ];
    if let Ok(result) = rc.query(brid, None, "get_all_nodes", None, Some(&mut args)).await {
        if let RestResponse::Bytes(val) = result {
            let nodes = gtv::decode(&val).unwrap();
            println!("To Params = {:?}", <Params as Into<Vec<Params>>>::into(nodes.clone()));
            println!("To JSON = {:?}", nodes.to_json_value());
        }
    }
}

async fn do_query_gtv_using_params_2(rc: &RestClient<'_>, brid: &str) {
     if let Ok(RestResponse::Bytes(result)) = rc.query::<&str>(brid, None, "test_map_with_bytearray_key", None, None).await {
        let r = gtv::decode(&result).unwrap();
        println!("{}", r.to_json_value()[0][0].to_string());
        println!("{}", r.to_json_value()[0][1].to_string());
     }
}

async fn do_query_gtv_using_struct_and_handle_query_respose(rc: &RestClient<'_>, brid: &str) {
    // Query GTV with struct and handle query respose in JSON
    #[derive(Debug, serde::Serialize)]
    struct GetAllNodes {
        include_inactive: bool,
    }

    #[derive(Debug, Default, serde::Deserialize)]
    struct NodeInfo {
        api_url: String,
        host: String,
        port: i64,
        pubkey: String,
        territory: String
    }

    #[derive(Debug, Default, serde::Deserialize)]
    struct NodeProvider {
        active: i64,
        name: String,
        pubkey: String,
        system: i64,
        tier: String,
        url: String
    }

    #[derive(Debug, Default, serde::Deserialize)]
    struct Node {
        active: i64,
        info: NodeInfo,
        last_updated: i64,
        provider: NodeProvider
    }

    let gan = GetAllNodes {
        include_inactive: true
    };

    let mut args = Params::from_struct_to_vec(&gan);

    if let Ok(result) = rc.query(brid, None, "get_all_nodes", None, Some(&mut args)).await {
        if let RestResponse::Bytes(val) = result {
            let nodes = gtv::decode(&val).unwrap();
            println!("To Params = {:?}", nodes);
            println!("To JSON = {:?}", nodes.to_json_value());

            for node in <Params as Into<Vec<Params>>>::into(nodes) {
                let n: Node = node.to_struct().unwrap();
                println!("Node Tier: {:?}", n.provider.tier);
                println!("Node URL: {:?}", n.info.api_url);
            }
        }
    }
}

async fn send_unsign_transaction(rc: &RestClient<'_>, brid: &str) {
    let operations = vec![
        Operation::from_list("setBoolean".to_string(), vec![
            Params::Boolean(true)
            ])
    ];

    let tx = Transaction{
        blockchain_rid: hex::decode(brid).unwrap(),
        operations: Some(operations),
        ..Default::default()
    };

    let result = rc.send_transaction(&tx).await;

    if let Err(error) = result {
        println!("{:?}", error.error_json.unwrap());
    } else {
        println!("{:?}", result.unwrap());
    }
}

async fn send_sign_transaction(rc: &RestClient<'_>, brid: &str, privkey: &str) {
    let operations = vec![
        Operation::from_list("setBoolean".to_string(), vec![
            Params::Boolean(true)
            ]),
        Operation::from_list("nop".to_string(), vec![
            Params::Boolean(true)
            ])
    ];

    let mut tx = Transaction{
        blockchain_rid: hex::decode(brid).unwrap(),
        operations: Some(operations),
        ..Default::default()
    };

    if let Err(error) = tx.sign_from_raw_priv_key(privkey) {
        println!("TX sign error {:?}", error);
        return
    }

    let result = rc.send_transaction(&tx).await;

    if let Err(error) = result {
        println!("{:?}", error.error_json.unwrap());
    } else {
        println!("{:?}", result.unwrap());
    }
}

async fn send_multi_sign_transaction(rc: &RestClient<'_>, brid: &str, privkeys: &[&str]) {
    let operations = vec![
        Operation::from_list("setBoolean".to_string(), vec![
            Params::Boolean(true)
            ]),
        Operation::from_list("nop".to_string(), vec![
            Params::Boolean(true)
            ])
    ];

    let mut tx = Transaction{
        blockchain_rid: hex::decode(brid).unwrap(),
        operations: Some(operations),
        ..Default::default()
    };

    if let Err(error) = tx.multi_sign_from_raw_priv_keys(&privkeys) {
        println!("TX multi sign error {:?}", error);
        return
    }

    let result = rc.send_transaction(&tx).await;

    if let Err(error) = result {
        println!("{:?}", error.error_json.unwrap());
    } else {
        println!("{:?}", result.unwrap());
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let rc = RestClient{
        node_url: vec!["https://node4.devnet1.chromia.dev:7740"],
        ..Default::default()
    };

    let dc_chain = "58FE4D15AA5BDA450CC8E55F7ED63004AB1D2535A123F860D1643FD4108809E3";
    let my_chain = "7A37DD331AC8FED64EEFCCA231B0F975DE7F4371CE5CA44105A5B117DF6DE251";

    do_query_gtv_using_params(&rc, &dc_chain).await;
    do_query_gtv_using_params_2(&rc, &my_chain).await;
    do_query_gtv_using_struct_and_handle_query_respose(&rc, &dc_chain).await;
    send_unsign_transaction(&rc, &my_chain).await;
    send_sign_transaction(&rc, &my_chain,
        "76C4AD***" // Replace with actual private key
    ).await;
    send_multi_sign_transaction(&rc, &my_chain, &[
        "76C4AD***", // Replace with actual private key
        "CCB973***" // Replace with actual private key
    ]).await;
}