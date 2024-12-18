use std::collections::HashMap;
use std::env;
use std::io;
use reqwest::{ Response, Client };
use serde_json::Value;
use std::path::Path;
use std::fs::File;
use std::fs;
use std::io::Write;

const HOST: &str = "http://localhost:5000";

async fn make_request(client: &Client, data: &HashMap<&str, String>, endpoint: &str) -> Response {
    client.post(HOST.to_owned() +  endpoint)
        .json(&data)
        .send()
        .await.unwrap()
}

async fn get_request_json(request: Response) -> Value {
    request.json::<serde_json::Value>().await.unwrap()
}

fn get_input(input: &mut String, question: &str) -> String {
    println!("{}", question);
    io::stdin()
        .read_line(input)
        .expect("Failed to read line");
    let trimmed_input = input.trim().to_string();
    input.clear();
    trimmed_input
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let client = reqwest::Client::new();

    let mut input = String::new();

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
                let username = get_input(&mut input, "Please enter your desired username:");
                println!("Your desired username is: {}", username);

                let email = get_input(&mut input, "Please enter your email address:");
                println!("Your email address is: {}", email);

                let password = get_input(&mut input, "Please enter your password:");
                println!("Your password is: {}", password);

                let mut data = HashMap::new();
                data.insert("username", username);
                data.insert("password", password);
                data.insert("email", email);

                let create_account = make_request(&client, &data, "/api/auth/new").await;

                if create_account.status() == 201 {
                    let json_response = get_request_json(create_account).await;

                    if let Err(e) = qr2term::print_qr(json_response["url"].as_str().unwrap()) {
                        eprintln!("Error generating QR code: {}", e);
                    }

                    let otp_code = get_input(&mut input, "Please scan the QR code with a 2FA app of your choice and write the code below:");

                    let id = json_response["id"].as_str().unwrap().to_string();
                    data.clear();
                    data.insert("id", id);
                    data.insert("otp_code", otp_code);

                    let verify_account = make_request(&client, &data, "/api/auth/verify").await;

                    if verify_account.status() == 201 {
                        let json_response = get_request_json(verify_account).await;

                        println!("good")
                    }
                } else {
                    eprintln!("Account was not created")
                }
            }
        }
        "2fa" => {
            let otp_code = get_input(&mut input, "Please enter your 2fa code:");

            let mut data = HashMap::new();
            data.insert("otp_code", otp_code);
            data.insert("id", "0923681112".to_string());
            data.insert("otp_key", "L5C5ULZM2FMYEI5V6ZJ6FFPPVQPFY427".to_string());
            let verify_account = make_request(&client, &data, "/api/auth/verify").await;

            if verify_account.status() == 200 {
                let json_response = get_request_json(verify_account).await;

                let path = Path::new("./.env");

                let mut file = if !path.exists() {
                    File::create(&path)
                } else {
                    Ok(File::options()
                        .write(true)
                        .open(&path)
                        .expect("Failed to open file"))
                }.unwrap();

                if let Err(e) = file.write(format!("REFRESH_TOKEN=\"{}\"\nACCESS_TOKEN=\"{}\"", json_response["refresh_token"].as_str().unwrap().to_string(), json_response["access_token"].as_str().unwrap().to_string()).as_bytes()) {
                    println!("{}",e)
                }

                println!("{}", json_response)
            }
        }
        _ => {

        }
    }
    println!("{}", args[1]);
}