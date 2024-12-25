use serde_json::Value;
use std::path::Path;

fn main() {
    let data = r#"{"name": "TODOs", "children": [{"name": "folder1", "children": [{"children": [], "name": "cool", "todos": []}], "todos": [{"id": 0, "content": "wow", "completed": true}]}], "todos": [{"id": 1, "content": "nested stuff", "completed": false}]}"#;

    let v: Value = serde_json::from_str(data).unwrap();

    make_structure(v, 0);
    create_note();
}

const CHECKMARK: &str = "V";
const X: &str = "X";

fn make_structure(data: Value, level: i32) {
    let spacing = " ".repeat((level*4).try_into().unwrap());

    println!("{}In {}:", spacing, data["name"].as_str().unwrap());

    for todo in data["todos"].as_array().unwrap() {
        let spacing = " ".repeat(((level+1)*4).try_into().unwrap());

        print!("{}- [{}]: {} (ID: {})", spacing, if todo["completed"].as_bool().unwrap() { X } else { " " }, todo["content"], todo["id"])
    }
    println!("\n");

    let array = data["children"].as_array().unwrap();

    for item in array {
        make_structure(item.clone(), level + 1)
    }

}

fn create_note() {
    let path = Path::new(".");
    let mut new_path = path.join("a").join("..");
    println!("{}", new_path.to_str().unwrap())
}

/*
Running `target\debug\testing.exe`

TODOs:
    - [ ] "nested stuff" (ID: X:1)

    In folder1:
        - [X] "wow" (ID: V:0)

*/