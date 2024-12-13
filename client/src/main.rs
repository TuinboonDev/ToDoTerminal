use std::collections::HashMap;
use std::io;
use reqwest::{ Response, Client };
use serde_json::Value;
use std::path::Path;
use std::fs::File;
use std::fs;
use std::io::Write;
use dotenv::dotenv;
use std::io::BufRead;
use std::env;
use std::fs::OpenOptions;
use reqwest::header::*;

const HOST: &str = "http://localhost:5000";
const STORAGE_PATH: &str = "./.env";

async fn post_request(client: &Client, json: &HashMap<&str, String>, headers: HeaderMap, endpoint: &str) -> Response {
    client.post(HOST.to_owned() +  endpoint)
        .json(&json)
        .headers(headers.clone())
        .send()
        .await.unwrap()
}

async fn get_request(client: &Client, headers: HeaderMap, endpoint: &str) -> Response {
    client.get(HOST.to_owned() + endpoint)
        .headers(headers.clone())
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

fn write_env(key: &str, value: &str) {
    // let path = Path::new(STORAGE_PATH);

    // let mut file = if !path.exists() {
    //     File::create(&path)
    //         .expect("Failed to create file")
    // } else {
    //     File::options()
    //         .write(true)
    //         .append(true)
    //         .open(&path)
    //         .expect("Failed to open file")
    // };

    // if let Err(e) = file.write_all(text) {
    //     eprintln!("Failed to write to file: {}", e);
    // }

    let path = Path::new(STORAGE_PATH);

    let mut file = if !path.exists() {
        File::create(&path)
            .expect("Failed to create file")
    } else {
        File::open(&path)
            .expect("Failed to open file")
    };
    let reader = io::BufReader::new(file);
    
    let mut lines = Vec::new();
    let mut updated = false;

    for line in reader.lines() {
        let mut line = line.unwrap();
        if line.starts_with(&(key.to_owned() + "=")) {
            line = format!("{}=\"{}\"", key, value);
            updated = true;
        }
        lines.push(line);
    }

    if !updated {
        lines.push(format!("{}=\"{}\"", key, value));
    }

    let mut file = File::options()
        .write(true)
        .truncate(true)
        .open(path).expect("Failed to open file");
    
    for line in lines {
        writeln!(file, "{}", line).unwrap();
    }
}

fn read_env(key: &str) -> String {
    env::var(key).expect(format!("{} env variable is unset.", key).as_str())
}


#[tokio::main]
async fn main() {
    dotenv().ok();

    // let ID: String = read_env("ID");
    // let REFRESH_TOKEN: String = read_env("REFRESH_TOKEN");
    // let ACCESS_TOKEN: String = read_env("ACCESS_TOKEN");

    let args: Vec<String> = env::args().collect();
    let client = reqwest::Client::new();

    let mut input = String::new();

    println!("Usage: todoterminal <command> [arguments]");
    match args[1].as_str() {
        "create" => {

        }
        "delete" => {

        }
        "notes" => {
            if args[2] == "list" {
                let mut headers = HeaderMap::new();
                headers.insert(AUTHORIZATION, read_env("ACCESS_TOKEN").parse().unwrap());

                let notes = get_request(&client, headers, "/api/notes/get").await;
                let json_response = get_request_json(notes).await;

                println!("{}", json_response);
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

                let create_account = post_request(&client, &data, HeaderMap::new(), "/api/auth/new").await;

                if create_account.status() == 201 {
                    let json_response = get_request_json(create_account).await;

                    if let Err(e) = qr2term::print_qr(json_response["url"].as_str().unwrap()) {
                        eprintln!("Error generating QR code: {}", e);
                    }

                    let otp_code = get_input(&mut input, "Please scan the QR code with a 2FA app of your choice and write the code below:");

                    let id = json_response["id"].as_str().unwrap().to_string();
                    data.clear();
                    data.insert("id", id.clone());
                    data.insert("otp_code", otp_code);

                    let verify_account = post_request(&client, &data, HeaderMap::new(), "/api/auth/verify").await;

                    if verify_account.status() == 201 {
                        let json_response = get_request_json(verify_account).await;

                        write_env("ID", &id);
                        write_env("REFRESH_TOKEN", json_response["refresh_token"].as_str().unwrap());
                        write_env("ACCESS_TOKEN", json_response["access_token"].as_str().unwrap());

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
            
            data.insert("id", read_env("ID"));
            data.insert("otp_code", otp_code);
            
            let verify_account = post_request(&client, &data, HeaderMap::new(), "/api/auth/verify").await;

            let status = verify_account.status();
            let json_response = get_request_json(verify_account).await;

            if status == 200 {
                write_env("REFRESH_TOKEN", json_response["refresh_token"].as_str().unwrap());
                write_env("ACCESS_TOKEN", json_response["access_token"].as_str().unwrap());

                println!("{}", json_response)
            } else if status == 401 || status == 404 {
                eprintln!("Error: {}", json_response["error"].as_str().unwrap().to_string())
            } else {
                eprintln!("Unrecognized HTTP response code!")
            }
        }
        _ => {

        }
    }
    println!("{}", args[1]);
}