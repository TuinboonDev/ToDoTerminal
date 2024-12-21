use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use std::fs::File;
use std::fs;
use std::io::{ Write, BufRead};
use std::io;
use std::env;
use serde_json::Value;
use dotenv::dotenv;
use reqwest::header::*;
use reqwest::{ Response, Client };
use base64::prelude::*;
use chrono::Utc;
use regex::Regex;

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
    let path = Path::new(STORAGE_PATH);

    let file = if !path.exists() {
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
    env::var(key).expect(&format!("{} env variable is unset.", key))
}

fn get_tracked_files(dir: &str) -> Vec<String> {
    let output = Command::new("git")
        .arg("ls-files")
        .arg(dir)
        .output().unwrap();

    if !output.status.success() {
        eprintln!("Failed to get git files");
        return vec![]
    }

    let files = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.to_string())
        .collect();

    files
}

fn find_todo(file_path: &Path, regex: Regex) -> Vec<String> {
    let mut todos = Vec::new();
    
    let contents = fs::read_to_string(file_path).unwrap();

    for mat in regex.find_iter(&contents) {
        let start = mat.start();
        let line_number = contents[..start].lines().count();
        let matched_text = mat.as_str().trim();

        todos.push(format!("[{}:{}]: {}", file_path.display(), line_number + 1, matched_text));
    }

    todos
}

#[tokio::main]  
async fn main() {
    dotenv().ok();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: todoterminal <command> [arguments]");
        return
    }

    let client = reqwest::Client::new();

    let mut input = String::new();

    let access_token = read_env("ACCESS_TOKEN");
    let parts: Vec<&str> = access_token.split('.').collect();
    
    let mut refresh = false;

    if parts.len() == 3 {
        let padded_encoded = format!("{}{}", parts[1], "=".repeat((4 - parts[1].len() % 4) % 4));
        let decoded = BASE64_STANDARD.decode(padded_encoded).unwrap();

        let payload_string = &String::from_utf8(decoded).expect("Error converting bytes to string");
        let payload = serde_json::from_str::<serde_json::Value>(payload_string).unwrap();

        let expiry = payload["exp"].as_i64().unwrap();
        let current_time = Utc::now().timestamp();
        
        if current_time > expiry {
            refresh = true;
        }
    } else {
        refresh = true;
    }

    if refresh {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, read_env("REFRESH_TOKEN").parse().unwrap());
        let refresh = post_request(&client, &HashMap::new(), headers, "/api/auth/refresh").await;
        let status = refresh.status();
        let json = get_request_json(refresh).await;
    
        if status == 200 {
            write_env("ACCESS_TOKEN", json["access_token"].as_str().unwrap());
            println!("Succesfully refreshed access token.")
        } else if status == 400 {
            eprintln!("Error while refreshing access_token: {}\nPlease try to log in again", json["error"]);
            return
        }
    }
    
    
    match args[1].as_str() {
        "todos" => {
            if args[2] == "list" {
                let mut headers = HeaderMap::new();
                headers.insert(AUTHORIZATION, read_env("ACCESS_TOKEN").parse().unwrap());

                let todos = get_request(&client, headers, "/api/todos/get").await;
                let json_response = get_request_json(todos).await;

                println!("Todo:");
                if let Some(items) = json_response.as_array() {
                    for item in items {
                        println!("[{}]: {}", item["id"], item["content"]);
                    }
                }
            }
            if args[2] == "delete" {
                if args.get(3).is_none() {
                    eprintln!("No todo ID provided");
                    return
                }

                let mut headers = HeaderMap::new();
                headers.insert(AUTHORIZATION, read_env("ACCESS_TOKEN").parse().unwrap());

                let mut data = HashMap::new();
                data.insert("id", args.get(3).expect("Couldnt find argument").to_string());
                let delete = post_request(&client, &data, headers, "/api/todos/delete").await;
                let status = delete.status();
                let json = get_request_json(delete).await;

                if status == 200 {
                    println!("{}", json["message"].as_str().unwrap())
                } else if status == 401 {
                    println!("{}", json["error"].as_str().unwrap())
                }
            }
            if args[2] == "create" {
                let mut headers = HeaderMap::new();
                headers.insert(AUTHORIZATION, read_env("ACCESS_TOKEN").parse().unwrap());

                let mut data = HashMap::new();
                data.insert("content", args[3].clone());

                let create = post_request(&client, &data, headers, "/api/todos/create").await;
                let status = create.status();
                let json = get_request_json(create).await;

                if status == 201 {
                    println!("{}", json["message"].as_str().unwrap())
                } else if status == 401 {
                    println!("{}", json["error"].as_str().unwrap())
                }
            }
            if args[2] == "import" {
                let mut string_regex = get_input(&mut input, "(Optional) enter custom TODO matching regex:");
                let regex = if !string_regex.is_empty() {
                    Regex::new(&string_regex).expect("Invalid regex")
                } else {
                    Regex::new(r"(?:\/\/TODO:|# TODO:).*").expect("Invalid regex")
                };
 
                for file in get_tracked_files("../") {
                    println!("{:?}", file);
                    println!("{:?}", find_todo(Path::new(&file), regex.clone()))
                }
                if args[3] == "git" {

                } else if args[3] == "fs" {
//TODO:
                }
            }
        }
        "account" => {
            if args[2] == "login" {
                let username = get_input(&mut input, "Please enter your desired username:");
                println!("Your username is: {}", username);

                let email = get_input(&mut input, "Please enter your email address:");
                println!("Your email address is: {}", email);

                let password = get_input(&mut input, "Please enter your password:");
                println!("Your password is: {}", password);

                let mut data = HashMap::new();
                data.insert("username", username);
                data.insert("password", password);
                data.insert("email", email);

                let login = post_request(&client, &data, HeaderMap::new(), "/api/auth/login").await;
                let status = login.status();
                let json = get_request_json(login).await;

                if status == 200 {
                    println!("{}", json["message"].as_str().unwrap())
                } else if status == 401 {
                    eprintln!("Error while logging in: {}", json["error"].as_str().unwrap())
                }
            }
            if args[2] == "logout" {
                let mut headers = HeaderMap::new();
                headers.insert(AUTHORIZATION, read_env("ACCESS_TOKEN").parse().unwrap());

                let logout = get_request(&client, headers, "/api/auth/logout").await;

                let status = logout.status();
                let json = get_request_json(logout).await;

                if status == 200 {
                    println!("{}", json["message"].as_str().unwrap());
                    write_env("ACCESS_TOKEN", "");
                } else {
                    println!("Error while logging out: {}", json["error"].as_str().unwrap())
                }
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

                let create_account = post_request(&client, &data, HeaderMap::new(), "/api/auth/create").await;

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
            println!("Error recognizing command")
        }
    }
}