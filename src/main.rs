#![allow(dead_code, unused, unused_imports)]
use dotenvy::dotenv;
use std::env;

#[macro_use]
extern crate serde;
extern crate reqwest;
extern crate serde_json;

mod todo;

#[tokio::main]
async fn main() {
    dotenv().expect("A .env file is required. Please inspect the README.");

    let oauth_cred = todo::read_client_credentials_from_env()
        .expect("A .env file is required. Please inspect the README.");

    todo::start_server(oauth_cred).await;
}
