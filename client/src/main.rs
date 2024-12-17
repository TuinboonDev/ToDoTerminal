use std::collections::HashMap;
use std::env;
use std::io;

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
                let mut input = String::new();
                println!("Please enter your desired username:");
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let username = input.trim().to_string(); 
                input.clear();
                println!("Your desired username is: {}", username);
                println!("Please enter your email address:");
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let email = input.trim().to_string();
                input.clear();
                println!("Your email address is: {}", email);
                println!("Please enter your password:");
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let password = input.trim().to_string();
                println!("Your password is: {}", password);
                input.clear();

                let mut data = HashMap::new();
                data.insert("username", username);
                data.insert("password", password);
                data.insert("email", email);
                let create_account = client.post(HOST.to_owned() +  "/api/auth/new")
                    .json(&data)
                    .send()
                    .await.unwrap();

                if create_account.status() == 201 {
                    let json_response = &create_account.json::<serde_json::Value>().await.unwrap();

                    qr2term::print_qr(json_response["url"].as_str().unwrap());
                    println!("{}", json_response["url"].as_str().unwrap());

                    println!("Please scan the QR code with a 2FA app of your choice and write the code below:");
                    io::stdin().read_line(&mut input).expect("Failed to read line");
                    let otp_code = input.trim().to_string();
                    input.clear();

                    let id = json_response["id"].as_str().unwrap().to_string();
                    data.clear();
                    data.insert("id", id);
                    data.insert("otp_code", otp_code);

                    let verify_account = client.post(HOST.to_owned() +  "/api/auth/verify")
                        .json(&data)
                        .send()
                        .await.unwrap();


                    if verify_account.status() == 201 {
                        let json_response = &verify_account.json::<serde_json::Value>().await.unwrap();

                        println!("good")
                    }
                } else {
                    eprintln!("Account was not created")
                }
            }
        }
        "2fa" => {
            let mut input = String::new();

            io::stdin().read_line(&mut input).expect("Failed to read line");
            let otp_code = input.trim().to_string();
            input.clear();

            let mut data = HashMap::new();
            data.insert("otp_code", otp_code);
            data.insert("id", "0923681112".to_string());
            data.insert("otp_key", "L5C5ULZM2FMYEI5V6ZJ6FFPPVQPFY427".to_string());
            let response = client.post(HOST.to_owned() +  "/api/auth/verify")
                .json(&data)
                .send()
                .await.unwrap();

            let json_response = &response.json::<serde_json::Value>().await.unwrap();


            println!("{}", json_response)
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