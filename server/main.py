from flask import Flask, json, request, jsonify
from dotenv import load_dotenv
from Crypto.Cipher import AES
import pyotp
import os
import jwt
import time
import bcrypt

# TODO: Write some library for parsing paths and make folders

load_dotenv()
app = Flask(__name__)

# cipher = AES.new(os.getenv("AES_KEY").encode("utf-8"), AES.MODE_EAX)
# ciphertext, tag = cipher.encrypt_and_digest(b"crazy")
# print(ciphertext)

# TODO: fix file opening/ closing race conditions
# TODO: use time instead of datetime for all expiry?
# TODO: change endpoints with simple data to use dynamic urls /api/cd/<idk>

SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_KEY")

def generate_access_token(user_id):
    return jwt.encode(
        {
            "user_id": user_id,
            "exp": int(time.time()) + 300
        },
        SECRET_KEY,
        algorithm="HS256"
    )

def generate_refresh_token(user_id, token_version):
    return jwt.encode(
        {
            "user_id": user_id,
            "exp": int(time.time()) + 604800,
            "token_version": token_version
        },
        REFRESH_SECRET_KEY,
        algorithm="HS256"
    )
    
def verify_token(token, secret):
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return "invalid"
    
def read_file(name):
    file = open(name, "r")
    content = json.load(file)
    
    file.close()
    
    return content 
    
def write_file(name, content):
    file = open(name, "w")

    file.seek(0)
    json.dump(content, file)
    file.truncate()
    file.close()
    
@app.route("/api/auth/create", methods=["POST"])
def create_user():
    user_data = request.json
    
    database = read_file("database.json")
    cache = read_file("cache.json")
        
    for user in database["users"]:
        if user["email"] == user_data["email"]:
            return json.dumps({"error": "An account with this email already exists."}), 409
        if user["username"] == user_data["username"]:
            return json.dumps({"error": "This username is already taken."}), 409
        
    # TODO: ig there could be duplicate IDs
    
    id = int(time.time())
    
    # TODO: Fix the user ID fields, they are kinda confusing here
    
    otp_key = pyotp.random_base32()
    
    if not id in database:
        for user in cache:
            if id >= user["expiry"]:
                cache.remove(user)
                
        password = user_data["password"].encode('utf-8')
        salt = bcrypt.gensalt()
        
        hashed_password = bcrypt.hashpw(password, salt)
                
        user_data["expiry"] = id + 1800
        user_data["id"] = str(id)
        user_data["otp_key"] = otp_key
        user_data["purpose"] = "new_account"
        user_data["password"] = password
        user_data["salt"] = salt
        user_data["cd"] = "/"
        cache.append(user_data)
        
        write_file("cache.json", cache)
        
        totp = pyotp.TOTP(otp_key)
        uri = totp.provisioning_uri(name="ToDoTerminal", issuer_name="2FA")
        
        return json.dumps({"url": uri, "id": str(id)}), 201
    else:
        return json.dumps({"message": "Account was deleted from cache after 30 minutes of inactivity, please create a new account."}), 410
        
@app.route("/api/auth/verify", methods=["POST"])
def verify_account():
    user_data = request.json

    cache = read_file("cache.json")
    database = read_file("database.json")
    todos = read_file("todos.json")
        
    for cache_user in cache:
        if cache_user["id"] == user_data["id"]:
            totp = pyotp.TOTP(cache_user["otp_key"])
            if totp.verify(user_data["otp_code"]):
                cache.remove(cache_user)
                    
                write_file("cache.json", cache)
                                        
                id = cache_user["id"]
                        
                match cache_user["purpose"]:
                    case "new_account":   
                        database["users"].append({
                            "username": cache_user["username"],
                            "password": cache_user["password"],
                            "email": cache_user["email"],
                            "otp_key": cache_user["otp_key"],
                            "salt": cache_user["salt"],
                            "id": id,
                            "token_version": 0
                        })
                        
                        if todos.get(id) == None:
                            todos[id] = {"count": 0, "todos": []}
                                
                        write_file("todos.json", todos)
                        write_file("database.json", database)
                        
                        access_token = generate_access_token(id)
                        refresh_token = generate_refresh_token(id, 0)
                        
                        return jsonify({"message": "Verification successful, account created.", "access_token": access_token, "refresh_token": refresh_token}), 201
                    
                    case "2fa":
                        access_token = generate_access_token(id)
                        refresh_token = generate_refresh_token(id, cache_user["token_version"])
                
                        return jsonify({"message": "Successfully authorized", "access_token": access_token, "refresh_token": refresh_token}), 200
                    
            else:
                return jsonify({"error": "Invalid OTP"}), 401
    return jsonify({"error": "User not found"}), 404
                            
@app.route("/api/auth/login", methods=["POST"])
def login():
    user_data = request.json

    database = read_file("database.json")
    cache = read_file("cache.json")
        
    for user in database["users"]:
        hashed_pw = bcrypt.hashpw(user_data["password"], user_data["salt"])
        if user["email"] == user_data["email"] and user["password"] == hashed_pw and user["username"] == user_data["username"]:
            x = int(time.time())

            for user in cache:
                if x >= user["expiry"]:
                    cache.remove(user)

            user["purpose"] = "2fa"
            user["expiry"] = x + 1800

            cache.append(user)
    
            write_file("cache.json", cache)
                        
            return json.dumps({"message": "Login successfull please follow with 2fa"}), 200
        
    return json.dumps({"error": "Invalid Credentials"}), 401
        
@app.route("/api/auth/logout", methods=["GET"])
def logout():
    database = read_file("database.json")

    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        
        for user in database["users"]:
            if user["id"] == user_id:
                user["token_version"] += 1
                
                write_file("database.json", database)
                
                return json.dumps({"message": "Successfully logged out"}), 200
            
    return json.dumps({"error": "User not found"}), 404               

@app.route("/api/auth/refresh", methods=["POST"])
def refresh_token():
    refresh_token = request.headers.get("Authorization")
    decoded = verify_token(refresh_token, REFRESH_SECRET_KEY)

    if decoded == "expired":
        return jsonify({"error": "Refresh token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:
        new_access_token = generate_access_token(decoded["user_id"])
        return jsonify({"access_token": new_access_token}), 200
    
@app.route("/api/todos/get", methods=["GET"])
def get_todos():
    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        
        todos_file = open("todos.json", "r")
        todos = json.load(todos_file)
                
        return todos[user_id]["todos"]
    
@app.route("/api/todos/create", methods=["POST"])
def create_todo():
    todo_content = json.loads(request.data)["content"]
    
    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        
        todos = read_file("todos.json")
        
        todos[user_id]["todos"].append({"content": todo_content, "id": todos[user_id]["count"], "completed": False})
        
        todos[user_id]["count"] += 1

        write_file("todos.json", todos)
    
        return json.dumps({"message": "Successfully created new todo"}), 201

@app.route("/api/todos/delete", methods=["POST"])
def delete_todo():
    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        todo_id = int(json.loads(request.data)["id"])
        
        todos = read_file("todos.json")
                
        for todo in todos[user_id]["todos"]:
            if todo["id"] == todo_id:
                todos[user_id]["todos"].remove(todo)
            
        write_file("todos.json", todos)
        
        return jsonify({"message": "Succesfully deleted todo"}), 200

@app.route("/api/todos/complete", methods=["POST"])
def complete_todo():
    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        todo_id = int(json.loads(request.data)["id"])
        
        todos = read_file("todos.json")
                
        for todo in todos[user_id]["todos"]:
            if todo["id"] == todo_id:
                todo["completed"] = True
            
        write_file("todos.json", todos)
        
        return jsonify({"message": "Succesfully completed todo"}), 200

@app.route("/api/todos/uncomplete", methods=["POST"])
def uncomplete_todo():
    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        todo_id = int(json.loads(request.data)["id"])
        
        todos = read_file("todos.json")
                
        for todo in todos[user_id]["todos"]:
            if todo["id"] == todo_id:
                todo["completed"] = False
            
        write_file("todos.json", todos)
        
        return jsonify({"message": "Succesfully uncompleted todo"}), 200
    
# @app.route("/api/cd", methods=["GET", "POST"])
# def cd():
#     access_token = request.headers.get("Authorization")
#     decoded = verify_token(access_token, SECRET_KEY)
    
#     if decoded == "expired":
#         return jsonify({"error": "Access token expired"}), 401
#     elif decoded == "invalid":
#         return jsonify({"error": "Invalid token"}), 401
#     else:
#         user_id = decoded["user_id"]        
#         database = read_file("database.json")
        
#         for user in database["users"]:
#             if user["id"] == user_id:
#                 if request.method == "GET":
#                     return jsonify({"cd": user["cd"]}), 200
                
#                 elif request.method == "POST":
#                     user["cd"] = json.loads(request.data)["cd"]
#                     return jsonify({"message": "Success"}), 200    
                    
#         return jsonify({"error": "User not found"}), 404            

# TODO: add breaks in loops if an item is found

if __name__ == "__main__":
    app.run(debug=True)