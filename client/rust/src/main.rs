use std::collections::HashMap;

const HOST: &str = "http://localhost:5000";
const ENDPOINT: &str = "/api/new";

fn make_request(host: &str) {

}

#[tokio::main]
async fn main() {
    let client = reqwest::Client::new();
    let what = client.post(HOST.to_owned() +  ENDPOINT)
        .body("{\"what\": \"crazy\"}")
        .send()
        .await.unwrap();
    if what.status() != 201 {
        println!("You bum!")
    }

    println!("{what:#?}");
}