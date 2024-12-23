use serde_json::Value;

fn main() {
    let data = r#"{"name": "TODOs", "children": [{"name": "folder1", "children": [], "todos": [{"id": 0, "content": "wow", "completed": true}]}], "todos": [{"id": 1, "content": "nested stuff", "completed": false}]}"#;

    let v: Value = serde_json::from_str(data).unwrap();

    make_structure(v, 0)
}

const CHECKMARK: &str = "V";
const X: &str = "X";

fn make_structure(data: Value, level: i32) {
    let spacing = " ".repeat((level*4).try_into().unwrap());

    println!("{}{}:", spacing, data["name"].as_str().unwrap());

    for todo in data["todos"].as_array().unwrap() {
        let spacing = " ".repeat(((level+1)*4).try_into().unwrap());

        print!("{}[{}:{}]: {}", spacing, if todo["completed"].as_bool().unwrap() { CHECKMARK } else { X }, todo["id"], todo["content"])
    }
    println!("\n");

    let array = data["children"].as_array().unwrap();

    if !array.is_empty() {
        for item in array {
            make_structure(item.clone(), level + 1)
        }
    }
}