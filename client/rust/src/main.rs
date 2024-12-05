use std::collections::HashMap;
use std::env;

const HOST: &str = "http://localhost:5000";
const ENDPOINT: &str = "/api/new";

fn make_request(host: &str) {

}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let client = reqwest::Client::new();
    println!("Usage: todoterminal <command> [arguments]");
    match args[1].as_str() {
        "create" => {

        }
        "delete" => {

        }
        "list" => {
            if args.len() > 2 {
                println!("No extra arguments needed");
            }
            
        }
        "account" => {
            if args[2] == "login" {

            }
            if args[2] == "create" {
                let mut line = String::new();
                println!("Enter your name :");
                let b1 = std::io::stdin().read_line(&mut line).unwrap();
                // let what = client.post(HOST.to_owned() +  ENDPOINT)
                //     .body("{\"what\": \"crazy\"}")
                //     .send()
                //     .await.unwrap();
                // if what.status() != 201 {
                //     println!("You bum!")
                // }
            }
        }
        _ => {

        }
    }
    println!("{}", args[1]);
    // let client = reqwest::Client::new();
    // let what = client.post(HOST.to_owned() +  ENDPOINT)
    //     .body("{\"what\": \"crazy\"}")
    //     .send()
    //     .await.unwrap();
    // if what.status() != 201 {
    //     println!("You bum!")
    // }

    // println!("{what:#?}");
}