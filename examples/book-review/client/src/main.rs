
use postchain_client::{
    utils::{operation::{Params, Operation}, transaction::Transaction},
    transport::client::{RestResponse, RestClient},
    encoding::gtv
};

use postchain_client::utils::operation::StructMetadata;

use tokio;

#[derive(Debug, Default, serde::Deserialize, serde::Serialize, postchain_client::StructMetadata)]
struct Book {
    isbn: String,
    title: String,
    author: String,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize, postchain_client::StructMetadata)]
struct BookReview {
    index: String,
    reviewer_name: String,
    review: String,
    rating: i64
}

use tracing_subscriber;

const PRIV_KEY: &str = "C70D5A77CC10552019179B7390545C46647C9FCA1B6485850F2B913F87270300";

async fn get_all_books(brid: &String, rc: &RestClient<'_>) {
    println!("Get all books query");
    let resp = rc.query::<&str>(&brid, None, "get_all_books", None, None).await;

    if let Ok(val) = resp {
        if let RestResponse::Bytes(val1) = val {
            if let Ok(d) = gtv::decode(&val1) {
                let vec: Vec<Params> = d.into();
                for v in vec {
                    let result: Result<Book, _> = v.to_struct();
                    if let Ok(book) = result {
                        println!("---");
                        println!("isbn = {}", book.isbn);
                        println!("title = {}", book.title);
                        println!("author = {}", book.author);
                        println!("---");
                    }
                }
            }
        }
    }
}

async fn create_new_books(brid: &String, rc: &RestClient<'_>) {
    println!("Create books");
    let mut books = Vec::new(); 

    for i in 0..3 {
        books.push(Book {
            isbn: format!("ISBN{}", i + 1),
            title: format!("Book{}", i + 1),
            author: format!("Author{}", i + 1),
        });
    }

    let mut operations = Vec::new();

    for book in &books {
        let param = Params::from_struct_to_list(book);
        operations.push(Operation::from_list("create_book".to_string(), param));
    }

    let brid_vec = hex::decode(brid.clone()).unwrap();

    let tx = Transaction{
        blockchain_rid: brid_vec,
        operations: Some(operations),
        ..Default::default()
    };

    let resp = rc.send_transaction(&tx).await;
    println!("{:?}", resp);
    println!("* Transaction sent!\n* Waiting for status...");
    
    let tx_status = rc.get_transaction_status(brid, &tx.tx_rid_hex().unwrap()).await;
    println!("* Status: {:?}", tx_status);
}

async fn create_book_review(brid: &String, rc: &RestClient<'_>) {
    println!("Create book review");

    let book_review = BookReview {
        index: "ISBN1".to_string(),
        reviewer_name: "Cuong Le".to_string(),
        review: "This is a great book!".to_string(),
        rating: 5,        
    };

    let param = Params::from_struct_to_list(&book_review);

    let operations = vec![
        Operation::from_list("create_book_review".to_string(), param),
        Operation::from_list("nop".to_string(), vec![])
    ];

    let brid_vec = hex::decode(brid.clone()).unwrap();

    let mut tx = Transaction{
        blockchain_rid: brid_vec,
        operations: Some(operations),
        ..Default::default()
    };

    let result = tx.sign_from_raw_priv_key(&PRIV_KEY);

     if let Err(error) = result {
        println!("{:?}", error);
     } else {
        let resp = rc.send_transaction(&tx).await;
        println!("{:?}", resp);
        let tx_status = rc.get_transaction_status(brid, &tx.tx_rid_hex().unwrap()).await;
        println!("{:?}", tx_status);
     }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let rc = RestClient{
        node_url: vec!["http://localhost:7740"],
        ..Default::default()
    };

    let get_blockchain_rid = rc.get_blockchain_rid(0).await;

    if let Ok(brid) = get_blockchain_rid {
        println!("Found BRID = {:?}", brid);
        create_new_books(&brid, &rc).await;
        create_book_review(&brid, &rc).await;
        get_all_books(&brid, &rc).await;
        
    } else {
        println!("{:?}", get_blockchain_rid);
    }
}
