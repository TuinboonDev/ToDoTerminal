use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use std::fs::File;
use std::fs;
use std::io::{ Write, BufRead};
use std::io;
use std::env;
use serde_json::Value;
use dotenvy::from_path_override;
use reqwest::header::*;
use reqwest::{ Response, Client };
use base64::prelude::*;
use chrono::Utc;
use regex::Regex;

const CHECKMARK: &str = "V";
const X: &str = "X";

async fn post_request(client: &Client, json: &HashMap<&str, String>, headers: HeaderMap, endpoint: &str) -> Response {
    client.post(read_env("HOST").to_owned() +  endpoint)
        .json(&json)
        .headers(headers)
        .send()
        .await.unwrap()
}

async fn get_request(client: &Client, headers: HeaderMap, endpoint: &str) -> Response {
    client.get(read_env("HOST").to_owned() + endpoint)
        .headers(headers)
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
    let env_path = if read_env("CREDS").is_empty() {
        "./.env"
    } else {
        &read_env("CREDS")
    };

    let path = Path::new(env_path);

    let file = if !path.exists() {
        File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .expect("Failed to create and open file")
    } else {
        File::options()
            .read(true)
            .write(true)
            .open(path)
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
    from_path_override(env_path).ok();
}

fn read_env(key: &str) -> String {
    env::var(key).unwrap_or("".to_string())
}

fn get_tracked_files(dir: &str) -> Vec<String> {
    let absolute_path = fs::canonicalize(dir).unwrap();
    let output = Command::new("git")
        .arg("ls-files")
        .current_dir(absolute_path)
        .output().unwrap();

    if !output.status.success() {
        println!("Couldn't find any tracked files, make sure this folder is a git repo.");
        return vec![]
    }

    let files = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.to_string())
        .collect();

    files
}

fn find_todo(path: &str, file: &str, regex: Regex, repo_name: &str) -> Vec<String> {
    let binding = path.to_owned() + "/" + file;
    let file_path = Path::new(&binding);

    if file_path.display().to_string().ends_with(".png") {
        return vec![]
    }
    let mut todos = Vec::new();
    
    let contents = fs::read_to_string(file_path);

    if !contents.is_ok() {
        return vec![]
    }

    let contents = contents.unwrap();

    for caps in regex.captures_iter(&contents) {
        if let Some(matched) = caps.get(1) { // Group 1 contains the captured TODO text
            let start = matched.start();
            let line_number = contents[..start].lines().count();
            let matched_text = matched.as_str().trim();

            todos.push(format!(
                "[{}:{}]: {}",
                repo_name.to_owned() + "/" + file,
                line_number + 1,
                matched_text
            ));
        }
    }

    todos
}

// fn make_todo_structure(data: Value, level: i32) {
//     let spacing = " ".repeat((level*4).try_into().unwrap());

//     println!("{}In {}:", spacing, data["name"].as_str().unwrap());

//     for todo in data["todos"].as_array().unwrap() {
//         let spacing = " ".repeat(((level+1)*4).try_into().unwrap());

//         print!("{}- [{}]: {} (ID: {})", spacing, if todo["completed"].as_bool().unwrap() { X } else { " " }, todo["content"], todo["id"])
//     }
//     println!("\n");

//     let array = data["children"].as_array().unwrap();

//     if !array.is_empty() {
//         for item in array {
//             make_todo_structure(item.clone(), level + 1)
//         }
//     }
// }

#[tokio::main]  
async fn main() {
    let env_path = if read_env("CREDS").is_empty() {
        "./.env"
    } else {
        &read_env("CREDS")
    };
    from_path_override(env_path).ok();

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

    let refresh_token = read_env("REFRESH_TOKEN");
    //let id = read_env("ID");
    let url = read_env("HOST");

    if refresh_token.is_empty() {
        if args.get(1) != Some(&"2fa".to_string()) && args.get(2) != Some(&"login".to_string()) && args.get(2) != Some(&"create".to_string()) {
            eprintln!("No refresh token found, please login.");
            return
        }
        refresh = false;
    }
    // if id.is_empty() {
    //     if args.get(1) != Some(&"2fa".to_string()) && args.get(2) != Some(&"login".to_string()) && args.get(2) != Some(&"create".to_string()) {
    //         eprintln!("No ID found, please login.");
    //         return
    //     }
    // }
    if url.is_empty() {
        eprintln!("No server link found, please add one in the env file to get started!");
        return
    }

    if refresh {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, refresh_token.parse().unwrap());
        
        let refresh = post_request(&client, &HashMap::new(), headers, "/api/auth/refresh").await;
        let status = refresh.status();
        let json = get_request_json(refresh).await;
    
        if status == 200 {
            write_env("ACCESS_TOKEN", json["access_token"].as_str().unwrap());
            println!("Succesfully refreshed access token.");
        } else if status == 400 {
            eprintln!("Error while refreshing access_token: {}\nPlease try to log in again", json["error"]);
            return
        }
    }
    
    // Some of these checks above and below are probably unneeded.
    if args.get(2) == Some(&"create".to_string()) && (!access_token.is_empty() || !refresh_token.is_empty()) {
        let another = get_input(&mut input, "You already have an account are you sure you want to create another one? (Y/n)");
        if another.to_lowercase() == "n" {
            println!("\nClosing!");
            return
        }
    }

    let access_token = read_env("ACCESS_TOKEN");
    // We can assume the access token exists because it has just been written
    
    match args[1].as_str() {
        // "cd" => {
        //     if args.len() < 3 {
        //         println!("Please provide a path");
        //         return
        //     }

        //     env::set_var("DIRECTORY", "");
        //     let mut headers = HeaderMap::new();
        //     headers.insert(AUTHORIZATION, read_env("ACCESS_TOKEN").parse().unwrap());
        //     let mut data = HashMap::new();
        //     data.insert("cd", args[2].clone());
        //     let refresh = post_request(&client, &data, headers, "/api/cd").await;
        // }
        "todos" => {
            if args.len() < 3 {
                println!("Missing argument after \"todos\".");
                return
            }

            match args[2].as_str() {
                "list" => {
                    if args.len() > 3 {
                        println!("Extra argument after \"list\" was unneeded.");
                        return
                    }

                    let mut headers = HeaderMap::new();
                    headers.insert(AUTHORIZATION, access_token.parse().unwrap());

                    let todos = get_request(&client, headers, "/api/todos/get").await;
                    let status = todos.status();
                    let json = get_request_json(todos).await;

                    if status == 200 {
                        println!("Your TODOs:");
                        if let Some(items) = json.as_array() {
                            for item in items {
                                println!("[{}:{}]: {}", if item["completed"].as_bool().unwrap() { CHECKMARK } else { X }, item["id"], item["content"]);
                            }
                        }
                    } else if status == 401 {
                        println!("{}", json["error"].as_str().unwrap())
                    }
                    
                }
                "delete" => {
                    let mut headers = HeaderMap::new();
                    headers.insert(AUTHORIZATION, access_token.parse().unwrap());

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
                "create" => {
                    let mut headers = HeaderMap::new();
                    headers.insert(AUTHORIZATION, access_token.parse().unwrap());

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
                // TODO: Fix wonky import code
                "import" => {
                    if args.len() < 5 {
                        println!("Usage: todoterminal todos import <fs|git> <path|github url> [clone dest]");
                        return
                    }
                    let path = if args[3] == "git" {
                        if args.get(5).is_none() {
                            println!("Please provide a desination path to copy the repo too")
                        }
                        let output = Command::new("git")
                            .arg("clone")
                            .arg(args[4].clone())
                            .arg(args[5].clone())
                            .output().unwrap();

                        if !output.status.success() {
                            eprintln!("Failed to clone git repo: {:?}", String::from_utf8_lossy(&output.stderr));
                            return
                        }

                        args[5].clone()
                    } else if args[3] == "fs" {
                        args[4].clone()
                    } else {
                        ".".to_string()
                    };

                    let string_regex = get_input(&mut input, "(Optional) enter custom TODO matching regex:");
                    let regex = if !string_regex.is_empty() {
                        Regex::new(&string_regex).expect("Invalid regex")
                    } else {
                        Regex::new(r"(?:\/\/ TODO:|# TODO:)(.*)").expect("Invalid regex")
                    };
    
                    let mut success = true;
                    let tracked_files = get_tracked_files(&path);

                    let output = Command::new("git")
                        .arg("rev-parse")
                        .arg("--show-toplevel")
                        .output()
                        .expect("Failed to execute git command");

                    if !output.status.success() {
                        eprintln!("Failed to retreive repo name: {:?}", String::from_utf8_lossy(&output.stderr));
                        return
                    }

                    let repo_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    let repo_name = repo_root.split('/').last().unwrap_or_default();

                    for file in &tracked_files {
                        for todo in find_todo(&path, &file, regex.clone(), repo_name) {
                            let mut headers = HeaderMap::new();
                            headers.insert(AUTHORIZATION, access_token.parse().unwrap());

                            let mut data = HashMap::new();
                            data.insert("content", todo);

                            let create = post_request(&client, &data, headers, "/api/todos/create").await;
                            let status = create.status();
                            let json = get_request_json(create).await;

                            if status == 401 {
                                success = false;
                                println!("{}", json["error"].as_str().unwrap())
                            }
                        }
                    }

                    if success && !tracked_files.is_empty() {
                        println!("Successfully imported all TODOs")
                    }
                }
                "complete" => {
                    let mut headers = HeaderMap::new();
                    headers.insert(AUTHORIZATION, access_token.parse().unwrap());

                    let mut data = HashMap::new();
                    data.insert("id", args.get(3).expect("Couldnt find argument").to_string());
                    let complete = post_request(&client, &data, headers, "/api/todos/complete").await;
                    let status = complete.status();
                    let json = get_request_json(complete).await;

                    if status == 200 {
                        println!("{}", json["message"].as_str().unwrap())
                    } else if status == 401 {
                        println!("{}", json["error"].as_str().unwrap())
                    }
                }
                "uncomplete" => {
                    let mut headers = HeaderMap::new();
                    headers.insert(AUTHORIZATION, access_token.parse().unwrap());

                    let mut data = HashMap::new();
                    data.insert("id", args.get(3).expect("Couldnt find argument").to_string());
                    let uncomplete = post_request(&client, &data, headers, "/api/todos/uncomplete").await;
                    let status = uncomplete.status();
                    let json = get_request_json(uncomplete).await;

                    if status == 200 {
                        println!("{}", json["message"].as_str().unwrap())
                    } else if status == 401 {
                        println!("{}", json["error"].as_str().unwrap())
                    }
                }
                e => {
                    println!("Error recognizing subcommand \"{}\"", e)
                }
            }
        }
        "account" => {
            match args[2].as_str() {
                "login" => {
                    let username = get_input(&mut input, "Please enter your username:");
                    println!("Your username is: {}\n", username);

                    let email = get_input(&mut input, "Please enter your email address:");
                    println!("Your email address is: {}\n", email);
                    // let mail_match = Regex::new(r"^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$").unwrap();
                    // if mail_match.is_match(&email) {
                    //     println!("Your email address is: {}", email);
                    // } else {
                    //     println!("Error: mail is in incorrect format!")
                    // }

                    let password = get_input(&mut input, "Please enter your password:");
                    println!("Your password is: {}\n", password);

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
                "logout" => {
                    let mut headers = HeaderMap::new();
                    headers.insert(AUTHORIZATION, access_token.parse().unwrap());

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
                "create" => {
                    let username = get_input(&mut input, "Please enter your desired username:");
                    println!("Your username is: {}\n", username);

                    let email = get_input(&mut input, "NOTE: Emails are unimplemented\nPlease enter your email address:");
                    println!("Your email address is: {}\n", email);

                    let password = get_input(&mut input, "Please enter your password:");
                    println!("Your password is: {}\n", password);

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

                            println!("\n2FA successful")
                        }
                    } else {
                        eprintln!("Account was not created")
                    }
                },
                e => {
                    println!("Error recognizing subcommand \"{}\"", e)
                }
            }
        }
        "2fa" => {
            let otp_code = get_input(&mut input, "Please enter your 2fa code:");
            let identification = get_input(&mut input, "\nPlease enter your username:");

            let mut data = HashMap::new();
            
            data.insert("identification", identification);
            data.insert("otp_code", otp_code);
            
            let verify_account = post_request(&client, &data, HeaderMap::new(), "/api/auth/verify").await;

            let status = verify_account.status();
            let json_response = get_request_json(verify_account).await;

            if status == 200 {
                write_env("REFRESH_TOKEN", json_response["refresh_token"].as_str().unwrap());
                write_env("ACCESS_TOKEN", json_response["access_token"].as_str().unwrap());
            } else if status == 401 || status == 404 {
                eprintln!("Error: {}", json_response["error"].as_str().unwrap().to_string())
            } else {
                eprintln!("Unrecognized HTTP response code!")
            }
        }
        e => {
            println!("Error recognizing subcommand \"{}\"", e)
        }
    }
}